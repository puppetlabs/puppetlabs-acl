# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Identity' do
  [
    { id: 'S-1-15-2-1',
      acl_regx: %r{.*APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)},
      minimum_kernel: 6.3 },
    # NOTE: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES' doesn't work due to Windows API
    { id: 'ALL APPLICATION PACKAGES',
      acl_regx: %r{.*APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)},
      minimum_kernel: 6.3 },
    { id: 'S-1-15-2-2',
      acl_regx: %r{.*APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)},
      minimum_kernel: 10.0 },
    # NOTE: 'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES' doesn't work due to Windows API
    { id: 'ALL RESTRICTED APPLICATION PACKAGES',
      acl_regx: %r{.*APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:\(OI\)\(CI\)\(F\)},
      minimum_kernel: 10.0 },
  ].each do |account|
    target = "c:/#{SecureRandom.uuid}"
    verify_acl_command = "icacls #{target}"

    context 'specify APPLICATION PACKAGE AUTHORITY accounts' do
      it "Check Minimum Supported OS for #{account[:id]}" do
        # use of host_inventory returns nil with localhost
        kernelmajversion = run_shell('facter kernelmajversion').stdout.to_f

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

          it 'applies manifest' do
            apply_manifest(acl_manifest, expect_failures) do |result|
              expect(result.exit_code).to eq(2)
            end
            apply_manifest(acl_manifest, catch_changes: true)
          end

          original_acl_rights = ''
          it 'verifies ACL rights' do
            run_shell(verify_acl_command) do |result|
              original_acl_rights = result.stdout
              expect(original_acl_rights).to match(%r{#{account[:acl_regx]}})
            end
          end

          it 'applies manifest again, raises error' do
            apply_manifest(acl_manifest, expect_failures: true) do |result|
              expect(result.stderr).to match(%r{Error:})
            end
          end

          it 'verifies ACL rights again' do
            run_shell(verify_acl_command) do |result|
              expect(result.stdout).to match(%r{account[:acl_regx]})
              expect(result.stdout).to eq(original_acl_rights)
            end
          end
        end
      end
    end
  end
end
