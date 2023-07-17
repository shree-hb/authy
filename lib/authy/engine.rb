require 'devise'
module Authy
  class Engine < ::Rails::Engine
    isolate_namespace Authy
    require "active_support/dependencies"

    
  end
end
