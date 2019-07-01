require 'spec_helper_acceptance'

describe 'Identity - Negative' do
  def acl_manifest(target_file, file_content, id)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def verify_content_command(target_file)
    "cat /cygdrive/c/temp/#{target_file}"
  end

  context 'Specify 257 Character String for Identity' do
    target_file = 'specify_257_char_ident.txt'
    group_id = 'nzxncvkjnzxjkcnvkjzxncvkjznxckjvnzxkjncvzxnvckjnzxkjcnvkjzxncvkjzxncvkjzxncvkjnzxkjcnvkzjxncvkjzxnvckjnzxkjcvnzxkncjvjkzxncvkjzxnvckjnzxjkcvnzxkjncvkjzxncvjkzxncvkjzxnkvcjnzxjkcvnkzxjncvkjzxncvkzckjvnzxkcvnjzxjkcnvzjxkncvkjzxnvkjsdnjkvnzxkjcnvkjznvkjxcbvzsp' # rubocop:disable Metrics/LineLength
    file_content = 'A bag of jerks.'

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Manifest' do
          execute_manifest_on(agent, acl_manifest(target_file, file_content, group_id), debug: true) do |result|
            assert_match(%r{Error: Failed to set permissions for }, result.stderr, 'Expected error was not detected!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command(target_file)) do |result|
            assert_match(file_content_regex(file_content), result.stdout, 'Expected file content is invalid!')
          end
        end
      end
    end
  end

  context 'Specify Invalid Identity' do
    target_file = 'specify_invalid_ident.txt'
    user_id = 'user_not_here'
    file_content = 'Car made of cats.'

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Manifest' do
          execute_manifest_on(agent, acl_manifest(target_file, file_content, user_id), debug: true) do |result|
            assert_match(%r{Error: Failed to set permissions for 'user_not_here'}, result.stderr, 'Expected error was not detected!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command(target_file)) do |result|
            assert_match(file_content_regex(file_content), result.stdout, 'Expected file content is invalid!')
          end
        end
      end
    end
  end
end
