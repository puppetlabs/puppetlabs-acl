require 'spec_helper_acceptance'

describe 'Windows ACL Module - Explicit Use of "target" Parameter' do
  let(:target) { 'c:/temp/explicit_target' }
  let(:verify_acl_command) { "icacls #{target}" }
  let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { 'explicit_target':
        target => '#{target}',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  windows_agents.each do |agent|
    context "on #{agent}" do
      include_examples 'execute manifest', agent
    end
  end
end
