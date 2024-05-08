import pyshark

# OID and extension identifiers for finding the attributes we're interested in
COMMON_NAME_OID = '2.5.4.3'
ORG_NAME_OID = '2.5.4.10'
LOCALITY_OID = '2.5.4.7'
STATE_PROVINCE_OID = '2.5.4.8'
COUNTRY_OID = '2.5.4.6'
ALT_NAME_EXT_ID = '2.5.29.17'

# TLS type constants
HANDSHAKE_CONTENT_TYPE = '22'
CERTIFICATE_HANDSHAKE_TYPE = '11'

# Takes a filename and extracts relevant information from all certificates present in the file
def extract_cert_information_from_pcap(pcap_file):
    
    cert_dict = dict()

    # Load the file, filtering only on packets which contain certificates
    # JSON loading speeds up the load process and keep_packets=False keeps memory usage down
    capture = pyshark.FileCapture(pcap_file, keep_packets=False, use_json=True, display_filter="tls.handshake.certificate")

    for packet in capture:

        # Ensure the packet has TLS records, which should be ensured by the filter
        if hasattr(packet, "tls") and packet.tls is not None:
            if hasattr(packet.tls, "record"):  

                certs_in_packet = list()

                # The record may be a list of records or a single record depending on packet structure
                if isinstance(packet.tls.record, list):
                    for record_layer in packet.tls.record:
                        new_certs = parse_cert_from_record(record_layer.record)
                        certs_in_packet.extend(new_certs)
                else:
                    if hasattr(packet.tls.record, "content_type"):
                        new_certs = parse_cert_from_record(packet.tls.record)
                        certs_in_packet.extend(new_certs)

                # Now process the certs in the packet
                for cert in certs_in_packet:
                    serial = cert.signedCertificate_element.serialNumber

                    # Key off serial which will be unique
                    if not serial in cert_dict:
                        
                        attributes = dict()

                        # Fetch all RDN elements from the subject field
                        rdn_tree = cert.signedCertificate_element.subject_tree.rdnSequence_tree.RDNSequence_item_tree

                        # May be a list of RDNs or a single one
                        if isinstance(rdn_tree, list):
                            for layer in rdn_tree:
                                attr_name, attr_value = extract_attribute_from_RDNItem(layer.RelativeDistinguishedName_item_element)
                                if attr_name != None:
                                    attributes[attr_name] = attr_value

                        else:
                            attr_name, attr_value = extract_attribute_from_RDNItem(rdn_tree.RelativeDistinguishedName_item_element)
                            if attr_name != None:
                                attributes[attr_name] = attr_value

                        # Now fetch alt names from the extneions
                        if hasattr(cert.signedCertificate_element, "extensions_tree"):
                            altnames = extract_altnames_from_extensions(cert.signedCertificate_element.extensions_tree)
                            if len(altnames) > 0:
                                attributes["altNames"] = altnames

                        # Store results
                        cert_dict[serial] = attributes

    # Final result
    return cert_dict

# Takes a TLS record and parses certificates if it contains any
def parse_cert_from_record(record_layer):
    cert_list = list()
    
    # Verify the content type is the "handshake" type
    if hasattr(record_layer, "content_type"):
        if record_layer.content_type == HANDSHAKE_CONTENT_TYPE:
            if hasattr(record_layer, "handshake"):

                # There may be more than one handshake
                if isinstance(record_layer.handshake, list):
                    for handshake_layer in record_layer.handshake:

                        # Verify the handshake is of type "certificate"
                        if handshake_layer.handshake.type == CERTIFICATE_HANDSHAKE_TYPE:
                            cert_list.append(handshake_layer.handshake.certificates.certificate_tree[0])
                else:

                    # Verify the handshake is of type "certificate"
                    if record_layer.handshake.type == CERTIFICATE_HANDSHAKE_TYPE:
                        cert_list.append(record_layer.handshake.certificates.certificate_tree[0])
        
    return cert_list

# Takes an RDN and sees if we care about the attribute
def extract_attribute_from_RDNItem(rdn_item):
    
    oid = rdn_item.oid

    # OIDs we care about are:
    # - common name
    # - org name
    # - locality
    # - state/province
    # - country

    # Attributes may be represented as a printable string or uTF8String

    if oid == COMMON_NAME_OID:
        if hasattr(rdn_item.DirectoryString_tree, "printableString"):
            commonName = rdn_item.DirectoryString_tree.printableString
        elif hasattr(rdn_item.DirectoryString_tree, "uTF8String"):
            commonName = rdn_item.DirectoryString_tree.uTF8String
        return "commonName", commonName
    
    if oid == ORG_NAME_OID:
        if hasattr(rdn_item.DirectoryString_tree, "printableString"):
            orgName = rdn_item.DirectoryString_tree.printableString
        elif hasattr(rdn_item.DirectoryString_tree, "uTF8String"):
            orgName = rdn_item.DirectoryString_tree.uTF8String
        return "orgName", orgName
    
    if oid == LOCALITY_OID:
        if hasattr(rdn_item.DirectoryString_tree, "printableString"):
            locality = rdn_item.DirectoryString_tree.printableString
        elif hasattr(rdn_item.DirectoryString_tree, "uTF8String"):
            locality = rdn_item.DirectoryString_tree.uTF8String
        return "locality", locality
    
    if oid == STATE_PROVINCE_OID:
        if hasattr(rdn_item.DirectoryString_tree, "printableString"):
            stateProvince = rdn_item.DirectoryString_tree.printableString
        elif hasattr(rdn_item.DirectoryString_tree, "uTF8String"):
            stateProvince = rdn_item.DirectoryString_tree.uTF8String
        return "stateProvince", stateProvince
    
    if oid == COUNTRY_OID:
        countryName = rdn_item.CountryName
        return "countryName", countryName
    
    return None, None

# Extracts the alt names of the certificate if they exist
def extract_altnames_from_extensions(extensions_tree):
    
    altnames = list()
    general_name_tree = None

    # There may be multiple extensions
    if isinstance(extensions_tree.Extension_element, list):
        for extension in extensions_tree.Extension_element:

            # Verify the extension ID is for alt names
            if extension.id == ALT_NAME_EXT_ID:
                general_name_tree = extension.GeneralNames_tree.GeneralName_tree
                break
    else:
        # Verify the extension ID is for alt names
        if extensions_tree.Extension_element.id == ALT_NAME_EXT_ID:
            general_name_tree = extensions_tree.Extension_element.GeneralNames_tree.GeneralName_tree

    # Now parse general names, of which there may be multiple
    if general_name_tree != None:
        if isinstance(general_name_tree, list):
            for general_name in general_name_tree:
                altnames.append(general_name.dNSName)
        else:
            altnames.append(general_name_tree.dNSName)

    return altnames