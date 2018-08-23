require 'beaker-pe'
require 'beaker-puppet'
require 'beaker-rspec'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'
require 'beaker/testmode_switcher'
require 'beaker/testmode_switcher/dsl'

run_puppet_install_helper
configure_type_defaults_on(hosts)

install_ca_certs

proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, source: proj_root, module_name: 'acl')
end

def target_parent
  'c:/temp'
end

def user_id
  'bob'
end

def generate_random_username
  charset = Array('A'..'Z') + Array('a'..'z')
  Array.new(5) { charset.sample }.join
end

def file_content_regex(file_content)
  %r{\A#{file_content}\z}
end

def windows_agents
  agents.select { |agent| agent['platform'].include?('windows') }
end

def linux_agents
  agents.select { |agent| fact_on(agent, 'kernel') == 'Linux' }
end
