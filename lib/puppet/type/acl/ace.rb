require 'puppet/parameter/value_collection'

class Puppet::Type::Acl::Ace

  attr_accessor :identity
  attr_accessor :rights
  attr_accessor :type
  attr_accessor :child_types
  attr_accessor :affects

  def initialize(permission_hash)
    @identity = permission_hash["identity"]
    @rights = permission_hash["rights"]
    #newvalues(:full, :modify, :write, :list, :read, :execute)
    # binary hex flags
    @type = validate_and_return(permission_hash["type"] || "allow",:allow,:deny)
    @child_types = validate_and_return(permission_hash["child_types"] || "all",:all, :objects, :containers)
    @affects = validate_and_return(permission_hash["affects"] || "all",:all, :self_only, :children_only, :self_and_direct_children, :direct_children_only)
  end

  def validate_and_return(value,*allowed_values)
    validator = Puppet::Parameter::ValueCollection.new
    validator.newvalues(*allowed_values)
    validator.validate(value)

    return value
  end

end
