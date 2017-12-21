require 'spec_helper_acceptance'

describe 'Use Cases' do

  def acl_manifest(target, file_content, user_id_1, user_id_2, user_id_3, user_id_4, user_id_5, user_id_6)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }
      
      user { "#{user_id_1}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_2}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_3}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_4}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_5}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_6}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id_1}', perm_type => 'allow', rights => ['full'] },
          { identity => '#{user_id_2}', perm_type => 'deny', rights => ['modify'] },
          { identity => '#{user_id_3}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{user_id_4}', perm_type => 'deny', rights => ['read','execute'] },
          { identity => '#{user_id_5}', perm_type => 'allow', rights => ['write','execute'] },
          { identity => '#{user_id_6}', perm_type => 'deny', rights => ['write','read'] }
        ],
      }
    MANIFEST
  end

  context 'Multiple ACEs for Target Path' do
    test_short_name = 'multi_aces'
    file_content = 'Ninjas all up in my face!'
    target_name = "use_case_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"

    user_id_1 = 'bob'
    user_id_2 = generate_random_username
    user_id_3 = 'billy'
    user_id_4 = 'sarah'
    user_id_5 = 'sally'
    user_id_6 = 'betty'

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"

    verify_acl_command = "icacls #{target}"
    user_id_1_ace_regex = /.*\\bob:\(F\)/
    user_id_2_ace_regex = /.*\\#{user_id_2}:\(DENY\)\(M\)/
    user_id_3_ace_regex = /.*\\billy:\(R\)/
    user_id_4_ace_regex = /.*\\sarah:\(DENY\)\(RX\)/
    user_id_5_ace_regex = /.*\\sally:\(W,Rc,X,RA\)/
    user_id_6_ace_regex = /.*\\betty:\(DENY\)\(R,W\)/

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, file_content, user_id_1, user_id_2, user_id_3, user_id_4, user_id_5, user_id_6)) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id_3_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id_4_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id_5_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id_6_ace_regex, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
          end
        end
      end
    end
  end
end
