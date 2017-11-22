require 'spec_helper_acceptance'

describe 'Use Cases' do

  def acl_manifest(target, target_child, target_grand_child, group_1, group_2, user_id_1, user_id_2)
    return <<-MANIFEST
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
      
      file { "#{target_grand_child}":
        ensure  => directory,
        require => File['#{target_child}']
      }
      
      group { "#{group_1}":
        ensure => present
      }
      
      group { "#{group_2}":
        ensure => present
      }
      
      user { "#{user_id_1}":
        ensure     => present,
        groups     => ['Users', '#{group_1}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group_1}']
      }
      
      user { "#{user_id_2}":
        ensure     => present,
        groups     => ['Users', '#{group_2}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group_2}']
      }
      
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id_1}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{user_id_2}', perm_type => 'deny', rights => ['read','execute'] },
          { identity => '#{group_1}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{group_2}', perm_type => 'allow', rights => ['read'] }
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id_1}', perm_type => 'allow', rights => ['write'] },
          { identity => '#{user_id_2}', perm_type => 'deny', rights => ['write'] },
          { identity => '#{group_1}', perm_type => 'allow', rights => ['execute'] },
          { identity => '#{group_2}', perm_type => 'allow', rights => ['execute'] }
        ],
      }
      ->
      acl { "#{target_grand_child}":
        permissions  => [
          { identity => '#{user_id_1}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id_2}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{group_1}', perm_type => 'allow', rights => ['full'] },
          { identity => '#{group_2}', perm_type => 'allow', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Multiple ACL for Nested Paths with Varying Rights for Same Identity' do
    test_short_name = 'multi_acl_shared_ident'
    target_name = "use_case_#{test_short_name}"
    target_child_name = "use_case_child_#{test_short_name}"
    target_grand_child_name = "use_case_grand_child_#{test_short_name}"
    target = "#{target_parent}/#{target_name}"
    target_child = "#{target}/#{target_child_name}"
    target_grand_child = "#{target_child}/#{target_grand_child_name}"

    group_1 = 'jerks'
    group_2 = 'cool_peeps'

    user_id_1 = 'bob'
    user_id_2 = 'jerry'

    verify_acl_command = "icacls #{target}"
    verify_acl_child_command = "icacls #{target_child}"
    verify_acl_grand_child_command = "icacls #{target_grand_child}"

    target_group_1_ace_regex = /.*\\jerks:(\(I\))?\(OI\)\(CI\)\(R\)/
    target_group_2_ace_regex = /.*\\cool_peeps:(\(I\))?\(OI\)\(CI\)\(R\)/
    target_user_id_1_ace_regex = /.*\\bob:(\(I\))?\(OI\)\(CI\)\(R\)/
    target_user_id_2_ace_regex = /.*\\jerry:(\(I\))?\(OI\)\(CI\)\(DENY\)\(RX\)/

    target_child_group_1_ace_regex = /.*\\jerks:(\(I\))?\(OI\)\(CI\)\(Rc,S,X,RA\)/
    target_child_group_2_ace_regex = /.*\\cool_peeps:(\(I\))?\(OI\)\(CI\)\(Rc,S,X,RA\)/
    target_child_user_id_1_ace_regex = /.*\\bob:(\(I\))?\(OI\)\(CI\)\(W,Rc\)/
    target_child_user_id_2_ace_regex = /.*\\jerry:(\(I\))?\(OI\)\(CI\)\(DENY\)\(W,Rc\)/

    target_grand_child_group_1_ace_regex = /.*\\jerks:\(OI\)\(CI\)\(F\)/
    target_grand_child_group_2_ace_regex = /.*\\cool_peeps:\(OI\)\(CI\)\(F\)/
    target_grand_child_user_id_1_ace_regex = /.*\\bob:\(OI\)\(CI\)\(N\)/
    target_grand_child_user_id_2_ace_regex = /.*\\jerry:\(OI\)\(CI\)\(N\)/

    windows_agents.each do |agent|
      it 'Execute ACL Manifest' do
        on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, target_child, target_grand_child, group_1, group_2, user_id_1, user_id_2)) do |result|
          assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_match(target_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')
        end
      end

      it 'Verify that ACL Rights are Correct for Child' do
        on(agent, verify_acl_child_command) do |result|
          #ACL from parent(s) will still apply.
          assert_match(target_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')

          assert_match(target_child_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')
        end
      end

      it 'Verify that ACL Rights are Correct for Grand Child' do
        on(agent, verify_acl_grand_child_command) do |result|
          #ACL from parent(s) will still apply.
          assert_match(target_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')

          #ACL from parent(s) will still apply.
          assert_match(target_child_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_child_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')

          assert_match(target_grand_child_group_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_grand_child_group_2_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_grand_child_user_id_1_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_grand_child_user_id_2_ace_regex, result.stdout, 'Expected ACL was not present!')
        end
      end
    end
  end
end
