# frozen_string_literal: true

# Helper class used to represent ACL Rights
class Puppet::Type::Acl
  # Simple ACL Rights object
  class Rights
    attr_reader :value, :order

    def initialize(permission)
      return if permission.nil? || permission.empty?

      @value = permission.downcase.to_sym unless @value.is_a?(Symbol)
      right = {
        full: 0,
        modify: 1,
        write: 2,
        read: 3,
        execute: 4,
        mask_specific: 5
      }
      @order = right[@value]
    end
  end
end
