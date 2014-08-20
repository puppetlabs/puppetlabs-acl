test_name "Install ACL Module on Master"

step "Install FOSS"
install_puppet({ :version        =>  ENV['PUPPET_VERSION'] || '3.6.2',
                 :default_action => 'gem_install'                       })

step "Clone Git Repo on Master"
on(master, "mkdir -p #{master['distmoduledir']}")
on(master, "git clone https://github.com/puppetlabs/puppetlabs-acl.git /etc/puppet/modules/acl")

step "Plug-in Sync Each Agent"
with_puppet_running_on master, :main => { :verbose => true, :daemonize => true } do
  on agents, puppet("plugin download --server #{master}")
end
