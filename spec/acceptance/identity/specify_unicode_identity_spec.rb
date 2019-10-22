require 'spec_helper_acceptance'

describe 'Identity' do
  let(:acl_manifest_group) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      group { '#{group_id}':
        ensure => present,
      }

      acl { '#{target}':
        permissions  => [
          { identity => '#{group_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_manifest_user) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
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

      acl { '#{target}':
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_regex) { %r{^1$} }

  context 'Specify Group Name Containing Unicode for Identity' do
    prefix = SecureRandom.uuid.to_s
    let(:acl_manifest) { acl_manifest_group }
    let(:target) { "#{target_parent}/#{prefix}.txt" }
    let(:raw_group_id) { 'group_\uB81D\uB534\uC2AB\uC788\uCC98' }
    let(:group_id) { "group_\uB81D\uB534\uC2AB\uC788\uCC98" } # 렝딴슫있처
    let(:file_content) { 'Garbage bag full of money.' }
    let(:verify_acl_command) { "(Get-ACL '#{target}' | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match ('\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count" } # rubocop:disable Metrics/LineLength

    include_examples 'execute manifest and verify (with PowerShell)'
  end

  context 'Windows ACL Module - Specify User Name Containing Unicode for Identity' do
    prefix = SecureRandom.uuid.to_s
    let(:acl_manifest) { acl_manifest_user }
    let(:target) { "#{target_parent}/#{prefix}.txt" }
    let(:raw_user_id) { 'user_\uB81D\uB534\uC2AB\uC788\uCC98' }
    let(:user_id) { "user_\uB81D\uB534\uC2AB\uC788\uCC98" } # 렝딴슫있처
    let(:file_content) { 'Flying Spaghetti Monster wants to save your soul.' }
    let(:verify_acl_command) { "(Get-ACL '#{target}' | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match ('\\\\' + [regex]::Unescape(\"#{raw_user_id}\")) -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count" } # rubocop:disable Metrics/LineLength

    include_examples 'execute manifest and verify (with PowerShell)'
  end
end
