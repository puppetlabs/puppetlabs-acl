# frozen_string_literal: true

require 'spec_helper_acceptance'

random_username = generate_random_username

describe 'Purge' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
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

  context 'Purge All Other Permissions from File without Inheritance' do
    let(:target) { "#{target_parent}/purge_all_other_no_inherit.txt" }
    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:file_content) { 'All your base are belong to us.' }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:acl_regex_user_id1) { %r{.*\\bob:\(F\)} }

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{acl_regex_user_id1}})
      end
    end

    it 'executes purge' do
      apply_manifest(acl_manifest_purge, catch_failures: true)
    end
  end
end
