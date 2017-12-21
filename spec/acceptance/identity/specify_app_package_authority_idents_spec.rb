require 'spec_helper_acceptance'

describe 'Identity' do
  [
      {:id => 'S-1-15-2-1',
       :acl_regex => /.*APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)/,
       :minimum_kernel => 6.3,
      },
      # NOTE: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES' doesn't work due to Windows API
      {:id => 'ALL APPLICATION PACKAGES',
       :acl_regex => /.*APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)/,
       :minimum_kernel => 6.3,
      },
      {:id => 'S-1-15-2-2',
       :acl_regex => /.*APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)/,
       :minimum_kernel => 10.0,
      },
      # NOTE: 'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES' doesn't work due to Windows API
      {:id => 'ALL RESTRICTED APPLICATION PACKAGES',
       :acl_regex => /.*APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)/,
       :minimum_kernel => 10.0,
      },
  ].each do |account|

    target = "c:/#{SecureRandom.uuid}"
    verify_acl_command = "icacls #{target}"

    windows_agents.each do |agent|
      context "Specify APPLICATION PACKAGE AUTHORITY accounts on #{agent}" do
        it "Check Minimum Supported OS for #{account[:id]}" do
          kernelmajversion = on(agent, facter('kernelmajversion')).stdout.chomp.to_f
          # try next agent if user is unsupported on this Windows version
          if kernelmajversion < account[:minimum_kernel]
            warn("This test requires Windows kernel #{account[:minimum_kernel]} but this host only has #{kernelmajversion}")
            skip
            
            acl_manifest = <<-MANIFEST
              file { '#{target}':
                ensure => directory
              }
          
              acl { '#{target}':
                permissions => [
                  { identity => '#{account[:id]}', rights => ['full'] },
                  { identity => 'Administrators', rights => ['full'] },
                ],
              }
            MANIFEST

            it 'Execute ACL Manifest' do
              # exit code 2: The run succeeded, and some resources were changed.
              on(agent, puppet('apply', '--detailed-exitcodes'), :stdin => acl_manifest, :acceptable_exit_codes => [2]) do |result|
                assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
              end
            end

            original_acl_rights = ''
            it 'Verify that ACL Rights are Correct' do
              on(agent, verify_acl_command) do |result|
                original_acl_rights = result.stdout
                assert_match(account[:acl_regex], original_acl_rights, 'Expected ACL was not present!')
              end
            end

            it 'Execute ACL Manifest again' do
              on(agent, puppet('apply'), :stdin => acl_manifest, :acceptable_exit_codes => [0]) do |result|
                assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
              end
            end

            it 'Verify that ACL Rights are Correct again' do
              on(agent, verify_acl_command) do |result|
                assert_match(account[:acl_regex], result.stdout, 'Expected ACL was not present!')
                assert_equal(result.stdout, original_acl_rights)
              end
            end
          end
        end
      end
    end
  end
end

