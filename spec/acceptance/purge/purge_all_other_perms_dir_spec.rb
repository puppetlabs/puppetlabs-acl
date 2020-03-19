require 'spec_helper_acceptance'

random_username = generate_random_username

describe 'Purge' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { "#{user_id1}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id2}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id1}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_manifest_purge) do
    <<-MANIFEST
      acl { "#{target}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id2}', rights => ['full'] },
        ],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'Purge All Other Permissions from Directory without Inheritance' do
    let(:target) { "#{target_parent}/purge_all_other_no_inherit" }
    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:acl_regex_user_id1) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }
    let(:acl_regex_user_id2) { %r{\Ac:\/temp\/purge_all_other_no_inherit.*\\#{user_id2}:\(OI\)\(CI\)\(F\)(\\r|\\n|\r|\n)*Successfully} }

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{acl_regex_user_id1}})
      end
    end

    it 'executes purge' do
      acl_idempotent_apply(acl_manifest_purge)
    end

    it 'verifies ACL rights (post-purge)' do
      run_shell(verify_acl_command, acceptable_exit_codes: [0, 5]) do |result|
        expect(result.stdout).not_to match(acl_regex_user_id1)
        expect(result.stdout).to match(acl_regex_user_id2)
      end
    end
  end
end
