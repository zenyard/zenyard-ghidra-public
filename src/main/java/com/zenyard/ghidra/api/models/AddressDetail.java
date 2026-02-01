package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Range detail for an address.
 * 
 * NOTE: mirrors models.binary.AddressDetail in zenyard/src/models/binary.py
 */
public class AddressDetail extends RangeDetail {
    @SerializedName("address")
    private Address address;
    
    public AddressDetail() {
        super("address");
    }
    
    public AddressDetail(Address address) {
        super("address");
        this.address = address;
    }
    
    public Address getAddress() {
        return address;
    }
    
    public void setAddress(Address address) {
        this.address = address;
    }
}

