require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(target, file_content)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { "#{target}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] }
        ],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  def update_manifest(target)
    <<-MANIFEST
      file { "#{target}":
        ensure  => file,
        content => 'New Content'
      }
    MANIFEST
  end

  context 'Negative - Manage Locked Resource with ACL' do
    test_short_name = 'locked_resource'
    file_content = 'Why this hurt bad!'
    target_name = "use_case_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target, file_content), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Attempt to Update File' do
          execute_manifest_on(agent, update_manifest(target), { :debug => true }) do |result|
            assert_match(%r{Error:.*Permission denied}, result.stderr, 'Expected error was not detected!')
          end
        end
      end
    end
  end
end
