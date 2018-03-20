require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(group1, group2, user_id1, user_id2, target, target_child, target_grand_child, file_content)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      group { "#{group1}":
        ensure => present
      }

      group { "#{group2}":
        ensure => present
      }

      user { "#{user_id1}":
        ensure     => present,
        groups     => ['Users', '#{group1}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group1}']
      }

      user { "#{user_id2}":
        ensure     => present,
        groups     => ['Users', '#{group2}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group2}']
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }
      ->
      acl { "#{target}":
        purge           => 'true',
        permissions     => [
          {
            identity    => 'Administrators',
            perm_type => 'allow',
            rights => ['full']
          },
          { identity    => '#{user_id1}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'all'
          },
          { identity    => '#{user_id2}',
            perm_type   => 'deny',
            rights      => ['read','execute'],
            affects     => 'children_only',
            child_types => 'objects'
          },
          { identity    => '#{group1}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'containers'
          },
          { identity    => '#{group2}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'all'
          }
        ],
        inherit_parent_permissions => 'false'
      }
      ->
      file { "#{target_child}":
        ensure  => directory
      }
      ->
      acl { "#{target_child}":
        purge           => 'true',
        permissions     => [
          { identity    => '#{user_id1}',
            perm_type   => 'deny',
            rights      => ['modify'],
            affects     => 'children_only',
            child_types => 'objects'
          },
          { identity    => '#{user_id2}',
            perm_type   => 'allow',
            rights      => ['full'],
            affects     => 'children_only',
            child_types => 'containers'
          }
        ],
      }
      ->
      file { "#{target_grand_child}":
        ensure  => file,
        content => '#{file_content}'
      }
      ->
      acl { "#{target_grand_child}":
        permissions  => [
          { identity    => '#{group2}',
            perm_type   => 'deny',
            rights      => ['full'],
            affects     => 'self_only'
          }
        ],
      }
    MANIFEST
  end

  context 'Complex Propagation and Inheritance with Nested Paths' do
    test_short_name = 'complex_prop_inherit'
    file_content = 'Sight seeing blind people.'

    target_name = "use_case_#{test_short_name}"
    target_child_name = "use_case_child_#{test_short_name}"
    target_grand_child_name = "use_case_grand_child_#{test_short_name}.txt"

    target = "#{target_parent}/#{target_name}"
    target_child = "#{target}/#{target_child_name}"
    target_grand_child = "#{target_child}/#{target_grand_child_name}"

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}/#{target_child_name}/#{target_grand_child_name}"

    group1 = 'jerks'
    group2 = 'cool_peeps'

    user_id1 = 'bob'
    user_id2 = generate_random_username

    verify_acl_grand_child_command = "icacls #{target_grand_child}"

    target_grand_child_first_ace_regex = %r{.*\\cool_peeps:\(N\)}
    target_grand_child_second_ace_regex = %r{.*\\bob:\(I\)\(DENY\)\(M\)}
    target_grand_child_third_ace_regex = %r{.*\\Administrators:\(I\)\(F\)}
    target_grand_child_fourth_ace_regex = %r{.*\\bob:\(I\)\(R\)}
    target_grand_child_fifth_ace_regex = %r{.*\\#{user_id2}:\(I\)\(DENY\)\(RX\)}
    target_grand_child_sixth_ace_regex = %r{.*\\cool_peeps:\(I\)\(R\)}

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(group1, group2, user_id1, user_id2, target, target_child, target_grand_child, file_content), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct for Grand Child' do
          on(agent, verify_acl_grand_child_command) do |result|
            # We only need to check the grand child because we are only concerned with rights
            # propagating and inheriting.
            assert_match(target_grand_child_first_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_grand_child_second_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_grand_child_third_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_grand_child_fourth_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_grand_child_fifth_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_grand_child_sixth_ace_regex, result.stdout, 'Expected ACL was not present!')
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
