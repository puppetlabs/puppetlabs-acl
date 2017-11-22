require 'beaker-rspec'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'

run_puppet_install_helper

install_ca_certs

proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, :source => proj_root, :module_name => 'acl')
end

def target_parent
  'c:/temp'
end

def user_id
  'bob'
end

def file_content_regex(file_content)
  /\A#{file_content}\z/
end

def windows_agents
  agents.select { |agent| agent['platform'].include?('windows') }
end

def linux_agents
  agents.select { |agent| fact_on(agent, 'kernel') == 'Linux' }
end
