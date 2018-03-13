require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, file_content, group_id, target_file)
  context "on #{agent}" do
    it 'Execute Manifest' do
      on(agent, puppet('apply', '--debug'), stdin: acl_manifest_with_group(target_file, file_content, group_id)) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(target_file)) do |result|
        assert_match(acl_regex(group_id), result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(target_file)) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Identity - Group' do
  def acl_manifest_with_group(target_file, file_content, group_id)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      group { '#{group_id}':
        ensure => present,
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{group_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def acl_manifest_with_user(target_file, file_content, user_id)
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

  def acl_regex(group_id)
    %r{.*\\#{group_id}:\(F\)}
  end

  context 'Specify Group Identity' do
    target_file = 'specify_group_ident.txt'
    group_id = 'bobs'
    file_content = 'Cat barf.'

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, target_file)
    end
  end

  context 'Specify Group with Long Name for Identity' do
    target_file = 'specify_long_group_ident.txt'
    # 256 Characters
    group_id = 'nzxncvkjnzxjkcnvkjzxncvkjznxckjvnzxkjncvzxnvckjnzxkjcnvkjzxncvkjzxncvkjzxncvkjnzxkjcnvkzjxncvkjzxnvckjnzxkjcvnzxkncjvjkzxncvkjzxnvckjnzxjkcvnzxkjncvkjzxncvjkzxncvkjzxnkvcjnzxjkcvnkzxjncvkjzxncvkzckjvnzxkcvnjzxjkcnvzjxkncvkjzxnvkjsdnjkvnzxkjcnvkjznvkjxcbvzs' # rubocop:disable Metrics/LineLength
    file_content = 'Pretty little poodle dressed in noodles.'

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, target_file)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
