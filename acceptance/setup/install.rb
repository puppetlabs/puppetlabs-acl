require 'beaker/puppet_install_helper'

if ENV['SHA'].nil?
  step 'Install Puppet'
  run_puppet_install_helper
else
  step "Install puppet-agent..." do
    opts = {
      :puppet_collection    => 'PC1',
      :puppet_agent_sha     => ENV['SHA'],
      :puppet_agent_version => ENV['SUITE_VERSION'] || ENV['SHA']
    }
    install_puppet_agent_dev_repo_on(hosts, opts)
  end

  # make sure install is sane, beaker has already added puppet and ruby
  # to PATH in ~/.ssh/environment
  agents.each do |agent|
    on agent, puppet('--version')
  end
end

step 'Install Certs'
install_ca_certs

step 'Install Module'
proj_root = File.expand_path(File.join(File.dirname(__FILE__), '../..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, :source => proj_root, :module_name => 'acl')
end
