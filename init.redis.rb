require 'redis'
require 'mysql2-cs-bind'
db = Mysql2::Client.new(
  host: 'localhost',
  port: nil,
  username: 'root',
  password: nil,
  database: 'isu4_qualifier',
  reconnect: true,
)

users = Hash.new(0)
ips = Hash.new(0)
last_logins = {}

Redis.current.keys('isu4:*').each_slice(1000) { |keys| Redis.current.del(keys) }


db.xquery('SELECT * FROM login_log').each do |log|
  user_id, login, ip, ok, at = log.values_at('user_id', 'login', 'ip', 'succeeded', 'created_at')

  if ok == 1
    ips[ip] = 0
    users[login] = 0
    last_logins[login] = {ip: ip, at: at.to_i}
  else
    ips[ip] += 1
    users[login] += 1 if user_id
  end
end

ths = []

ths << Thread.new do
  last_logins.each do |k, vs|
    Redis.current.hmset("isu4:last:#{k}", vs.to_a.flatten)
  end
end

ths << Thread.new do
  users.each_slice(1000) do |pairs|
    Redis.current.mset(*pairs.flat_map {|v, c| ["isu4:user:#{v}", c] })
  end
end

ths << Thread.new do
  ips.each_slice(1000) do |pairs|
    Redis.current.mset(*pairs.flat_map {|v, c| ["isu4:ip:#{v}", c] })
  end
end

ths.each(&:join)

