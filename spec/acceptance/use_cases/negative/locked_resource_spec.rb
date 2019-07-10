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

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'applies manifest' do
          execute_manifest_on(agent, acl_manifest, debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'attempts to update file, raises error' do
          execute_manifest_on(agent, update_manifest, debug: true) do |result|
            expect(result.stderr).to match(%r{Error:.*Permission denied})
          end
        end
      end
    end
  end
end
