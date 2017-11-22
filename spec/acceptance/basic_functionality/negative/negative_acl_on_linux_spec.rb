require 'spec_helper_acceptance'

describe 'Basic Functionality - Negative' do

  acl_manifest = <<-MANIFEST
    file { '/tmp/acl_test':
      ensure => directory
    }

    acl { '/tmp/acl_test':
      permissions => [
        { identity => 'root', rights => ['full'] },
      ],
    }
  MANIFEST

  context 'ACL Fails Gracefully on Linux' do
    linux_agents.each do |agent|
      it "Verify that the 'acl' Type Does not Work on Non-Windows Agents on #{agent}" do
        on(agent, puppet('apply', '--debug'), :stdin => acl_manifest) do |result|
          assert_match(/Error: Could not find a suitable provider for acl/, result.stderr, 'Expected error was not detected!')
        end
      end
    end
  end
end
