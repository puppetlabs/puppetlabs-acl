require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
def apply_manifest_and_verify(agent, target, remove = false)
  context "on #{agent}" do
    verify_acl_command = "icacls #{target}"
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(F\)}
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(target), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end
    if remove
      it 'Execute Remove Manifest' do
        execute_manifest_on(agent, acl_manifest_remove(target), { :debug => true }) do |result|
          assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_no_match(acl_regex, result.stdout, 'Unexpected ACL was present!')
        end
      end
    end
  end
end

describe 'Permissions - Directory' do
  def acl_manifest(target)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def acl_manifest_remove(target)
    <<-MANIFEST
      acl { '#{target}':
        purge => 'listed_permissions',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Add Permissions to a Directory with a Long Name (247 chars)' do
    target = 'c:/temp/ybqYlVTjWTRAaQPPyeaseAsuUhnclarfedIpqIdqwyimqPphcKpojhTHogTUWiaEkiOqbeEZKvNAqDcEjJarQzeNxihARGLytPNseasKZxhRxeCwZsopSUFTKTAgsxsBqRigMlZhFQiELGLZghRwhKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSChEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrPhasdEfU' # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target)
    end
  end

  context 'Implicit Use of "target" Parameter Through Title' do
    target = 'c:/temp/implicit_target'

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target)
    end
  end

  context 'Remove Permissions from a Directory' do
    target = 'c:/temp/rem_perm_dir'

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target, true)
    end
  end

  context 'Remove Permissions from a Directory with a Long Name (247 chars)' do
    target = 'c:/temp/rem_lVTjWTRAaQPPyeaseAsuUhnclarfedIpqIdqwyimqPphcKpojhTHogTUWiaEkiOqbeEZKvNAqDcEjJarQzeNxihARGLytPNseasKZxhRxeCwZsopSUFTKTAgsxsBqRigMlZhFQiELGLZghRwhKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSChEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrPhasdEfU' # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target, true)
    end
  end

  context 'Add Permissions to a Unicode Directory' do
    prefix = SecureRandom.uuid.to_s
    raw_dirname = prefix + '_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158'
    dirname =     "#{prefix}_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158"
    target = "#{target_parent}/#{dirname}"

    verify_acl_command = "(Get-ACL ('#{target_parent}/' + [regex]::Unescape(\"#{raw_dirname}\")) | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match '\\\\bob' -and $_.FileSystemRights -eq 'FullControl' -and $_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' } | Measure-Object).Count" # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      it 'Execute Manifest' do
        execute_manifest_on(agent, acl_manifest(target), { :debug => true }) do |result|
          assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, powershell(verify_acl_command, 'EncodedCommand' => true)) do |result|
          assert_match(%r{^1$}, result.stdout, 'Expected ACL was not present!')
        end
      end
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
