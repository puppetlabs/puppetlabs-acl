# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Permissions - Directory' do
  let(:acl_manifest) do
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

  let(:acl_manifest_remove) do
    <<-MANIFEST
      acl { '#{target}':
        purge => 'listed_permissions',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target}" }
  let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

  context 'Add Permissions to a Directory with a Long Name (247 chars)' do
    let(:target) { 'c:/temp/ybqYlVTjWTRAaQPPyeaseAsuUhnclarfedIpqIdqwyimqPphcKpojhTHogTUWiaEkiOqbeEZKvNAqDcEjJarQzeNxihARGLytPNseasKZxhRxeCwZsopSUFTKTAgsxsBqRigMlZhFQiELGLZghRwhKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSChEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrPhasdEfU' } # rubocop:disable Layout/LineLength

    include_examples 'execute manifest'
  end

  context 'Implicit Use of "target" Parameter Through Title' do
    let(:target) { 'c:/temp/implicit_target' }

    include_examples 'execute manifest'
  end

  context 'Remove Permissions from a Directory' do
    let(:target) { 'c:/temp/rem_perm_dir' }

    include_examples 'execute manifest', true
  end

  context 'Remove Permissions from a Directory with a Long Name (247 chars)' do
    let(:target) { 'c:/temp/rem_lVTjWTRAaQPPyeaseAsuUhnclarfedIpqIdqwyimqPphcKpojhTHogTUWiaEkiOqbeEZKvNAqDcEjJarQzeNxihARGLytPNseasKZxhRxeCwZsopSUFTKTAgsxsBqRigMlZhFQiELGLZghRwhKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSChEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrPhasdEfU' } # rubocop:disable Layout/LineLength

    include_examples 'execute manifest', true
  end

  context 'Add Permissions to a Unicode Directory' do
    prefix = SecureRandom.uuid.to_s
    let(:raw_dirname) { prefix + '_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158' }
    let(:dirname) { "#{prefix}_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158" }
    let(:target) { "#{target_parent}/#{dirname}" }
    let(:verify_acl_command) { "(Get-ACL ('#{target_parent}/' + [regex]::Unescape(\"#{raw_dirname}\")) | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match '\\\\bob' -and $_.FileSystemRights -eq 'FullControl' -and $_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' } | Measure-Object).Count" } # rubocop:disable Layout/LineLength
    let(:acl_regex) { %r{^1$} }

    include_examples 'execute manifest and verify (with PowerShell)'
  end
end
