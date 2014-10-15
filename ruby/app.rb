require 'digest/sha2'
require 'rack/utils'
require 'rack/request'
require 'json'
require 'mysql2-cs-bind'
require 'erubis'

module Isucon4
  class App
    USER_LOCK_THRESHOLD = 3
    IP_BAN_THRESHOLD = 10

    VIEWS_DIR = "#{__dir__}/views"
    LAYOUT_REPLACER = '<%= yield %>'

    def self.users
      @users ||= {}
    end

    def self.view(name)
      @views ||= {}
      @views[name] ||= begin
        path = File.join(VIEWS_DIR, "#{name}.erb")
        Erubis::FastEruby.new(File.read(path)).tap do |erb|
          erb.filename = path
        end
      end
    end

    def self.layout(name)
      @layouts ||= {}
      e = @layouts[name]
      return e if e

      body = layout_(name) { LAYOUT_REPLACER }.split(LAYOUT_REPLACER).each(&:freeze)
      @layouts[name] = body
    end

    def self.layout_(name)
      view(name).result(binding)
    end

    INDEX_NORMAL = 0
    INDEX_LOCKED = 1
    INDEX_BANNED = 2
    INDEX_WRONG  = 3
    INDEX_MUST_LOGGED_IN = 4
    INDEX_VIEWS = [
      [nil],
      ["This account is locked."],
      ["You're banned."],
      ["Wrong username or password"],
      ["You must be logged in"],
    ].tap do |views|
      views.each do |body|
        body[0] = [layout(:base)[0], self.view(:index).evaluate(notice: body[0]), layout(:base)[1]].join.gsub(/^\s+/,'').gsub(/[\r\n]/,'')
      end
    end

    def self.call(env)
      self.new(env).call
    end

    def initialize(env)
      @env = env
      @status = nil
      @headers = {}
      @body = []
    end

    module ResponseMethods
      def response
        [@status || 200, @headers, @body]
      end

      def content_type(type)
        @headers['Content-Type'] = type
      end

      def render(template, layout = :base)
        @headers['Content-Type'] ||= 'text/html'
        @status ||= 200
        @body = erb(template, layout)
      end

      def erb(name, layout = :base)
        if layout
          l = App.layout(layout)
          [l[0], erb(name, nil)[0], l[1]]
        else
          [App.view(name).result(binding)]
        end
      end

      def not_found
        @status = 404
        @headers = {'Content-Type' => 'text/plain'}
        @body = ['not found']
      end

      def redirect(path)
        @status = 302
        @headers['Location'.freeze] = path
      end
    end

    module Helpers
      def request
        @request ||= Rack::Request.new(@env)
      end

      def request_ip
        @env['HTTP_X_FORWARDED_FOR'] || @env['REMOTE_ADDR']
      end

      def cookies
        @cookies ||= @env['HTTP_COOKIE'] ? @env['HTTP_COOKIE'].split(/;\s*/).map{|_| _.split('='.freeze,2) }.to_h : {}
      end

      def cookie_set(key, value)
        (@headers['Set-Cookie'] ||= '') << "#{key}=#{value};path=/\n"
      end

      def cookie_rem(key)
        (@headers['Set-Cookie'] ||= '') << "#{key}=;path=/;max-age=0\n"
      end

      def params
        @params ||= request.params
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def db
        Thread.current[:isu4_db] ||= Mysql2::Client.new(
          host: 'localhost',
          port: nil,
          username: 'root',
          password: nil,
          database: 'isu4_qualifier',
          reconnect: true,
        )
      end

      def get_user(login)
        db.xquery('SELECT * FROM users WHERE login = ?', login).first
      end

      def login_log(succeeded, login)
        db.xquery("INSERT INTO login_log" \
                  " (`created_at`, `login`, `ip`, `succeeded`)" \
                  " VALUES (?,?,?,?)",
                 Time.now, login, request.ip, succeeded ? 1 : 0)
      end

      def user_locked?(login)
        return nil unless login
        log = db.xquery("SELECT COUNT(1) AS failures FROM login_log WHERE login = ? AND id > IFNULL((select id from login_log where login = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);", login, login).first

        USER_LOCK_THRESHOLD <= log['failures']
      end

      def ip_banned?
        log = db.xquery("SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);", request.ip, request.ip).first

        IP_BAN_THRESHOLD <= log['failures']
      end

      def attempt_login(login, password)
        if ip_banned?
          login_log(false, login)
          return [nil, INDEX_BANNED]
        end

        user = get_user(login)
        p user

        case
        when !user
          login_log(false, login)
          [nil, INDEX_WRONG] # login
        when user_locked?(login)
          login_log(false, login)
          [nil, INDEX_LOCKED]
        when calculate_password_hash(password, user['salt']) == user['password_hash']
          login_log(true, login)
          [user, nil]
        else
          login_log(false, login)
          [nil, INDEX_WRONG] # pass
        end
      end

      def current_user
        return @current_user if @current_user
        login = cookies['login']
        return nil unless login

        @current_user = get_user(login)
        unless @current_user
          cookie_set 'login'.freeze, nil
          return nil
        end

        @current_user
      end

      def last_login
        @last_login ||= begin
          cur = current_user
          return nil unless cur

          db.xquery('SELECT * FROM login_log WHERE succeeded = 1 AND login = ? ORDER BY id DESC LIMIT 2', cur['login']).each.last
        end
      end

      def banned_ips
        ips = []
        threshold = IP_BAN_THRESHOLD

        not_succeeded = db.xquery('SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?', threshold)

        ips.concat not_succeeded.each.map { |r| r['ip'] }

        last_succeeds = db.xquery('SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip')

        last_succeeds.each do |row|
          count = db.xquery('SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id', row['ip'], row['last_login_id']).first['cnt']
          if threshold <= count
            ips << row['ip']
          end
        end

        ips
      end

      def locked_users
        logins = []
        threshold = USER_LOCK_THRESHOLD

        not_succeeded = db.xquery('SELECT login FROM (SELECT login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY login) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?', threshold)

        logins.concat not_succeeded.each.map { |r| r['login'] }

        last_succeeds = db.xquery('SELECT login, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP BY login')

        last_succeeds.each do |row|
          count = db.xquery('SELECT COUNT(1) AS cnt FROM login_log WHERE login = ? AND ? < id', row['login'], row['last_login_id']).first['cnt']
          if threshold <= count
            logins << row['login']
          end
        end
        
        logins.each_slice(500).flat_map { |slice|
          db.xquery('SELECT login FROM users WHERE login IN (?)', slice).map {|_| _['login'] }
        }
      end
    end

    module Actions
      def action_index
        content_type 'text/html'
        n = cookies['notice'.freeze]
        cookie_rem 'notice'.freeze if n
        @body = INDEX_VIEWS[n.to_i]
      end

      def action_login
        user, err = attempt_login(params['login'], params['password'])
        if user
          cookie_set 'login'.freeze, user['login']
          redirect '/mypage'.freeze
        else
          cookie_set 'notice'.freeze, err
          redirect '/'.freeze
        end
      end

      def action_mypage
        unless current_user
          cookie_set 'notice'.freeze, INDEX_MUST_LOGGED_IN
          return redirect '/'
        end

        @body = [
          '<!DOCTYPE html><html><head><meta charset="UTF-8"><link rel="stylesheet" href="/stylesheets/bootstrap.min.css"><link rel="stylesheet" href="/stylesheets/bootflat.min.css"><link rel="stylesheet" href="/stylesheets/isucon-bank.css"><title>isucon4</title></head><body><div class="container"><h1 id="topbar"><a href="/"><img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス"></a></h1><div class="alert alert-success" role="alert">ログインに成功しました。<br>未読のお知らせが０件、残っています。</div><dl class="dl-horizontal"><dt>前回ログイン</dt><dd id="last-logined-at">'.freeze,
          last_login['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
          '</dd><dt>最終ログインIPアドレス</dt><dd id="last-logined-ip">'.freeze,
          last_login['ip'],
          '</dd></dl><div class="panel panel-default"><div class="panel-heading">お客様ご契約ID：'.freeze,
          current_user['login'],
          '様の代表口座</div><div class="panel-body"><div class="row"><div class="col-sm-4">普通預金<br><small>東京支店　1111111111</small><br></div><div class="col-sm-4"><p id="zandaka" class="text-right">―――円</p></div><div class="col-sm-4"><p><a class="btn btn-success btn-block">入出金明細を表示</a><a class="btn btn-default btn-block">振込・振替はこちらから</a></p></div><div class="col-sm-12"><a class="btn btn-link btn-block">定期預金・住宅ローンのお申込みはこちら</a></div></div></div></div></div></body></html>'.freeze
        ]
      end

      def action_report
        content_type 'application/json'
        @body = [{
          banned_ips: banned_ips,
          locked_users: locked_users,
        }.to_json]
      end
    end

    include ResponseMethods
    include Helpers
    include Actions

    def call
      meth = @env['REQUEST_METHOD'.freeze]
      path = @env['PATH_INFO'.freeze]

      case
      when path == '/login'.freeze
        action_login
      when meth == 'GET'.freeze
        case path
        when '/'.freeze
          action_index
        when '/mypage'.freeze
          action_mypage
        when '/report'.freeze
          action_report
        else
          not_found
        end
      else
        not_found
      end

      response
    end
  end
end
