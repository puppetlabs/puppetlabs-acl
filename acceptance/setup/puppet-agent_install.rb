test_name "Install Puppet Agent"

version = ENV['PUPPET_AGENT_VERSION'] || '0.9.1'
download_url = ENV['WIN_DOWNLOAD_URL'] || 'http://builds.puppetlabs.lan/'
proj_root = File.expand_path(File.join(File.dirname(__FILE__), '../..'))
hosts.each do |host|
  if host['platform'] =~ /windows/
    step "Install foss from MSI"
    install_puppetagent_dev_repo(host,
                            {
                                :dev_builds_url => download_url,
                                :version => version
                            })

    on host, "mkdir -p #{host['distmoduledir']}/acl"
    result = on host, "echo #{host['distmoduledir']}/acl"
    target = result.raw_output.chomp
    step "Install ACL to host"
    %w(lib manifests metadata.json).each do |file|
      scp_to host, "#{proj_root}/#{file}", "#{target}"
    end
  end
end
