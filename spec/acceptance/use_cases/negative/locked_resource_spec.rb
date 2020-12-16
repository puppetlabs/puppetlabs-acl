# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_file}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { "#{target_parent}/#{target_file}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] }
        ],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  let(:update_manifest) do
    <<-MANIFEST
      file { "#{target_parent}/#{target_file}":
        ensure  => file,
        content => 'New Content'
      }
    MANIFEST
  end

  context 'Negative - Manage Locked Resource with ACL' do
    let(:test_short_name) { 'locked_resource' }
    let(:file_content) { 'Why this hurt bad!' }
    let(:target_file) { "use_case_#{test_short_name}.txt" }

    it 'applies manifest' do
      apply_manifest(acl_manifest, catch_failures: true)
    end

    it 'attempts to update file, raises error' do
      apply_manifest(update_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error:.*Permission denied})
      end
    end
  end
end
