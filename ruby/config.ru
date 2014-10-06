require_relative './app.rb'
require 'rack/session/cookie'

require 'stackprof' #if ENV['ISUPROFILE']
Dir.mkdir('/tmp/stackprof') unless File.exist?('/tmp/stackprof')
use StackProf::Middleware, enabled: ENV['ISUPROFILE'] == ?1, mode: :cpu, interval: 1000, save_every: 100, path: '/tmp/stackprof'

use Rack::Session::Cookie, secret: 'shirokane'

run Isucon4::App
