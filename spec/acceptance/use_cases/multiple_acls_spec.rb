require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(target, target_child, user_id1, user_id2, user_id3, user_id4, user_id5, user_id6)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      file { "#{target_child}":
        ensure  => directory,
        require => File['#{target}']
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

      user { "#{user_id3}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id4}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id5}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id6}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['modify'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id3}', perm_type => 'allow', rights => ['write'] }
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id4}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id5}', perm_type => 'allow', rights => ['modify'] },
          { identity => '#{user_id6}', perm_type => 'deny', rights => ['read'] }
        ],
      }
    MANIFEST
  end

  context 'ACL for Parent Path with Separate ACL for Child Path' do
    test_short_name = 'multi_acl'
    target_name = "use_case_#{test_short_name}"
    target_child_name = "use_case_child_#{test_short_name}"

    target = "#{target_parent}/#{target_name}"
    target_child = "#{target}/#{target_child_name}"

    user_id1 = 'bob'
    user_id2 = generate_random_username
    user_id3 = 'billy'
    user_id4 = 'sarah'
    user_id5 = 'sally'
    user_id6 = 'betty'

    verify_acl_command = "icacls #{target}"
    verify_acl_child_command = "icacls #{target_child}"
    user_id1_ace_regex = %r{.*\\bob:(\(I\))?\(OI\)\(CI\)\(M\)}
    user_id2_ace_regex = %r{.*\\#{user_id2}:(\(I\))?\(OI\)\(CI\)\(N\)}
    user_id3_ace_regex = %r{.*\\billy:(\(I\))?\(OI\)\(CI\)\(W,Rc\)}
    user_id4_ace_regex = %r{.*\\sarah:\(OI\)\(CI\)\(N\)}
    user_id5_ace_regex = %r{.*\\sally:\(OI\)\(CI\)\(M\)}
    user_id6_ace_regex = %r{.*\\betty:\(OI\)\(CI\)\(DENY\)\(R\)}

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target, target_child, user_id1, user_id2, user_id3, user_id4, user_id5, user_id6), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(user_id1_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id2_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id3_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_no_match(user_id4_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_no_match(user_id5_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_no_match(user_id6_ace_regex, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Verify that ACL Rights are Correct for Child' do
          on(agent, verify_acl_child_command) do |result|
            assert_match(user_id1_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id2_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id3_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id4_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id5_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(user_id6_ace_regex, result.stdout, 'Expected ACL was not present!')
          end
        end
      end
    end
  end
end
