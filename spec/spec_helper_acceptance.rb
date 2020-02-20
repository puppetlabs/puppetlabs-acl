# frozen_string_literal: true

require 'serverspec'
require 'puppet_litmus'
require 'pry'
require 'spec_helper_acceptance_local' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_local.rb'))

PuppetLitmus.configure!
