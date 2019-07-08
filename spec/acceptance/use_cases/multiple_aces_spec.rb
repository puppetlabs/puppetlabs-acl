require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(target, file_content, user_id1, user_id2, user_id3, user_id4, user_id5, user_id6)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
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
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['full'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['modify'] },
          { identity => '#{user_id3}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{user_id4}', perm_type => 'deny', rights => ['read','execute'] },
          { identity => '#{user_id5}', perm_type => 'allow', rights => ['write','execute'] },
          { identity => '#{user_id6}', perm_type => 'deny', rights => ['write','read'] }
        ],
      }
    MANIFEST
  end

  context 'Multiple ACEs for Target Path' do
    test_short_name = 'multi_aces'
    file_content = 'Ninjas all up in my face!'
    target_name = "use_case_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"

    user_id1 = 'bob'
    user_id2 = generate_random_username
    user_id3 = 'billy'
    user_id4 = 'sarah'
    user_id5 = 'sally'
    user_id6 = 'betty'

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"

    verify_acl_command = "icacls #{target}"
    user_id1_ace_regex = %r{.*\\bob:\(F\)}
    user_id2_ace_regex = %r{.*\\#{user_id2}:\(DENY\)\(M\)}
    user_id3_ace_regex = %r{.*\\billy:\(R\)}
    user_id4_ace_regex = %r{.*\\sarah:\(DENY\)\(RX\)}
    user_id5_ace_regex = %r{.*\\sally:\(W,Rc,X,RA\)}
    user_id6_ace_regex = %r{.*\\betty:\(DENY\)\(R,W\)}

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target, file_content, user_id1, user_id2, user_id3, user_id4, user_id5, user_id6), debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).to match(%r{#{user_id1_ace_regex}})
            expect(result.stdout).to match(%r{#{user_id2_ace_regex}})
            expect(result.stdout).to match(%r{#{user_id3_ace_regex}})
            expect(result.stdout).to match(%r{#{user_id4_ace_regex}})
            expect(result.stdout).to match(%r{#{user_id5_ace_regex}})
            expect(result.stdout).to match(%r{#{user_id6_ace_regex}})
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            expect(result.stdout).to match(%r{#{file_content_regex(file_content)}})
          end
        end
      end
    end
  end
end
