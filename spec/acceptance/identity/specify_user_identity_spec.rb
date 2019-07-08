require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, file_content, user_id, target_file)
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(file_content, user_id, target_file), debug: true) do |result|
        expect(result.stderr).not_to match(%r{Error:})
      end
    end
    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(target_file)) do |result|
        expect(result.stdout).to match(%r{#{acl_regex(user_id)}})
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(target_file)) do |result|
        expect(result.stdout).to match(%r{#{file_content_regex(file_content)}})
      end
    end
  end
end

describe 'Identity - User' do
  def acl_manifest(file_content, user_id, target_file)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def verify_content_command(target_file)
    "cat /cygdrive/c/temp/#{target_file}"
  end

  def verify_acl_command(target_file)
    "icacls #{target_parent}/#{target_file}"
  end

  def acl_regex(user_id)
    %r{.*\\#{user_id}:\(F\)}
  end

  context 'Specify User with Long Name for Identity' do
    target_file = 'specify_long_user_ident.txt'
    user_id = 'user_very_long_name1'
    file_content = 'Brown cow goes moo.'

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, user_id, target_file)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
