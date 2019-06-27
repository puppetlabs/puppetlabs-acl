require 'spec_helper_acceptance'

describe 'Windows ACL Module - Explicit Use of "target" Parameter' do
  target = 'c:/temp/explicit_target'
  verify_acl_command = "icacls #{target}"
  acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(F\)}

  acl_manifest = <<-MANIFEST
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

  windows_agents.each do |agent|
    context "on #{agent}" do
      it 'Execute Manifest' do
        execute_manifest_on(agent, acl_manifest, debug: true) do |result|
          assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
        end
      end
    end
  end
end
