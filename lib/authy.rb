# frozen_string_literal: true

require_relative "authy/version"
require "authy/engine"
require "active_support/dependencies"

module Authy
 
  def self.mounted_path
    ::Authy::Engine.mounted_path
  end

end
