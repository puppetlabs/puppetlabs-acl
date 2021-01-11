# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Basic Functionality - Negative' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '/tmp/acl_test':
        ensure => directory
      }

      acl { '/tmp/acl_test':
        permissions => [
          { identity => 'root', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'ACL Fails Gracefully on Linux', unless: os[:family] == 'windows' do
    it "verifes that the 'acl' type does not work on non-Windows agents" do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error: Could not find a suitable provider for acl})
      end
    end
  end
end
