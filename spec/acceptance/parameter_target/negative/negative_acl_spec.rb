require 'spec_helper_acceptance'

describe 'Parameter Target - Negative' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      ->
      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      ->
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Specify Blank Target' do
    let(:target) { '' }

    it 'applies manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error:.*(A non-empty name must be specified|Empty string title at)})
      end
    end
  end

  context 'Specify Target with Invalid Path Characters' do
    let(:target) { 'c:/temp/invalid_<:>|?*' }

    it 'applies manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error:.*The filename, directory name, or volume label syntax is incorrect})
      end
    end
  end
end
