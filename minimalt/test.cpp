#include <iostream>
#include <sodium.h>
#include <easylogging++.h>
#include <string>
#include <cstdint>
#include "crypto.h"
#include <map>
#include "minimalt.h"

_INITIALIZE_EASYLOGGINGPP

int main(int argc, const char ** argv) {
    sodium_init();  

    Key directory_long;
    Key directory_ephemeral;
    
    std::map<std::string, Certificate> directory_certificates;
    
    Key rubendvbe_long;
    Key rubendvbe_ephemeral;
    directory_certificates.insert(std::make_pair<std::string, Certificate>("directory", directory_long.certificate(directory_ephemeral.publicPart())));
    directory_certificates.insert(std::make_pair<std::string, Certificate>("rubendv.be:80", directory_long.certificate(rubendvbe_ephemeral.publicPart())));

    Key client_long;
    Key client_ephemeral;
    PublicKey directory_long_public = directory_long.publicPart();
    
    std::string identifier = "directory";
    std::uint64_t tunnel_id;
    randombytes_buf(reinterpret_cast<char *>(&tunnel_id), sizeof(tunnel_id));
    PublicMessage requestCertMessage = makeRequestCertMessage(tunnel_id, identifier, client_ephemeral, directory_long_public);
    PublicMessage requestCertMessageReceived(requestCertMessage.packetize());

    LOG(INFO) << requestCertMessage;
    LOG(INFO) << requestCertMessageReceived;
    Unboxed requestCertMessageReceivedUnboxed = requestCertMessageReceived.unbox(directory_long);
    LOG(INFO) << requestCertMessageReceivedUnboxed;

    PublicKey client_pk(requestCertMessageReceived.ephemeral_box_pk);

    PublicMessage provideCertMessage = makeProvideCertMessage(
        requestCertMessageReceived.tunnel_id, 
        directory_certificates[requestCertMessageReceivedUnboxed.message.substr(1)],
        directory_long,
        client_pk
    );
    std::string provideCertPacket = provideCertMessage.packetize();
    LOG(INFO) << "provideCertPacket: " << std::dec << provideCertPacket.size() << " bytes";
    PublicMessage provideCertMessageReceived = PublicMessage(provideCertPacket);
    
    LOG(INFO) << provideCertMessage;
    LOG(INFO) << provideCertMessageReceived;
    Unboxed provideCertMessageReceivedUnboxed = provideCertMessageReceived.unbox(client_ephemeral, directory_long_public);
    LOG(INFO) << provideCertMessageReceivedUnboxed;

    return 0;
}
