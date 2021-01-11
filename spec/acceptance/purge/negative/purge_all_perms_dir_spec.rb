# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Purge' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_file}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target_parent}/#{target_file}":
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_manifest_purge) do
    <<-MANIFEST
      acl { "#{target_parent}/#{target_file}":
        purge        => 'true',
        permissions  => [],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'Negative - Purge Absolutely All Permissions from Directory without Inheritance' do
    let(:target_file) { 'purge_all_no_inherit' }

    let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }
    let(:acl_regex_user_id) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

    let(:verify_purge_error) { %r{Error:.*Value for permissions should be an array with at least one element specified} }

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{acl_regex_user_id}})
      end
    end

    it 'attempts purge, raises error' do
      apply_manifest(acl_manifest_purge, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{#{verify_purge_error}})
      end
    end
  end
end
