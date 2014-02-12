require 'puppet/parameter/value_collection'

class Puppet::Type::Acl
  class Ace

    attr_accessor :identity
    attr_accessor :sid
    attr_accessor :rights
    attr_accessor :type
    attr_accessor :child_types
    attr_accessor :affects
    attr_accessor :is_inherited
    attr_accessor :mask

    def initialize(permission_hash)
      @sid = permission_hash['sid']
      @identity = validate_non_empty('identity',permission_hash['identity'] || permission_hash['sid'])
      @rights = validate_individual_values(
          validate_array(
            'rights',
            validate_non_empty('rights',permission_hash['rights'])
          ),
          :full, :modify, :write, :list, :read, :execute, :mask_specific)
      # binary hex flags
      @type = validate(permission_hash['type'] || 'allow', :allow, :deny)
      @child_types = validate(permission_hash['child_types'] || 'all', :all, :objects, :containers, :none)
      @affects = validate(permission_hash['affects'] || 'all', :all, :self_only, :children_only, :self_and_direct_children, :direct_children_only)
      @is_inherited = permission_hash['is_inherited'] || false
      @mask = permission_hash['mask']
    end

    def validate(value,*allowed_values)
      validator = Puppet::Parameter::ValueCollection.new
      validator.newvalues(*allowed_values)
      validator.validate(value)

      value
    end

    def is_inherited?
      return is_inherited
    end

    def validate_non_empty(name,value)
      if value.nil? or value == ''
        raise ArgumentError, "A non-empty #{name} must be specified."
      end
      if value.kind_of?(Array) and value.count == 0
        raise ArgumentError, "Value for #{name} should have least one element in the array."
      end

      value
    end

    def validate_array(name,values)
      raise ArgumentError, "Value for #{name} should be an array. Perhaps try ['#{values}']?" unless values.kind_of?(Array)

      values
    end

    def validate_individual_values(values,*allowed_values)
      values.each do |value|
        validate(value,*allowed_values)
      end

      values
    end

  end
end
