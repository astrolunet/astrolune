# The C++23 tooling tree: the Trocto/Regol contract-language compiler.

# The compiler links the core for container encoding, tagged hashing and
# authoritative validation - it must agree with the node byte-for-byte.
astrolune_add_tool_library(trocto
    SOURCES
        trocto/lexer.cpp
        trocto/encoder.cpp
        trocto/regol.cpp
        trocto/parser.cpp
        trocto/lower.cpp
        trocto/trocto.cpp
    DEPS Astrolune::core
)

astrolune_add_executable(trocto_cli
    LANG CXX
    SOURCES apps/trocto/main.cpp
    DEPS trocto
)
set_target_properties(trocto_cli PROPERTIES OUTPUT_NAME trocto)

# Astrolune Connect client — local DNS resolver + SOCKS5 proxy for .lune.
astrolune_add_tool_library(astrolune_connect_lib
    SOURCES
        ecosystem/connect/astrolune_connect.cpp
        ecosystem/dns/lune_resolver.cpp
        ecosystem/proxy/socks5_proxy.cpp
)

astrolune_add_executable(astrolune_connect_cli
    LANG CXX
    SOURCES apps/connect/main.cpp
    DEPS astrolune_connect_lib
)
set_target_properties(astrolune_connect_cli PROPERTIES OUTPUT_NAME astrolune-connect)

# Name indexer — indexes .lune domain registrations from blockchain events.
astrolune_add_tool_library(name_indexer_lib
    SOURCES
        ecosystem/indexer/name_indexer.cpp
    DEPS Astrolune::core
)

# Static .lune gateway — serves hosted websites via HTTP.
astrolune_add_tool_library(lune_gateway_lib
    SOURCES
        ecosystem/gateway/lune_gateway.cpp
    DEPS name_indexer_lib
)

# Content-addressed site manifest for static .lune hosting.
astrolune_add_tool_library(site_manifest_lib
    SOURCES
        ecosystem/hosting/site_manifest.cpp
    DEPS Astrolune::core
)

# Host node — stores and serves static site content.
astrolune_add_tool_library(host_node_lib
    SOURCES
        ecosystem/hosting/host_node.cpp
    DEPS site_manifest_lib Astrolune::core
)

# Publish CLI — deploys static websites to the content store.
astrolune_add_executable(publish_cli
    LANG CXX
    SOURCES apps/publish/main.cpp
    DEPS site_manifest_lib
)
set_target_properties(publish_cli PROPERTIES OUTPUT_NAME astrolune-publish)

# Share — file chunking, Merkle manifests, and chunk storage.
astrolune_add_tool_library(file_chunker_lib
    SOURCES
        ecosystem/share/file_chunker.cpp
    DEPS Astrolune::core
)

astrolune_add_tool_library(merkle_manifest_lib
    SOURCES
        ecosystem/share/merkle_manifest.cpp
    DEPS Astrolune::core
)

astrolune_add_tool_library(share_node_lib
    SOURCES
        ecosystem/share/share_node.cpp
    DEPS file_chunker_lib merkle_manifest_lib Astrolune::core
)

# Content encryption for paid share content.
astrolune_add_tool_library(content_encryptor_lib
    SOURCES
        ecosystem/share/content_encryptor.cpp
    DEPS Astrolune::core
)

# VPN / TUN interface for Astrolune Connect.
astrolune_add_tool_library(tun_interface_lib
    SOURCES
        ecosystem/vpn/tun_interface.cpp
)

# Proxy connector — reverse tunnel for self-hosted servers.
astrolune_add_tool_library(proxy_connector_lib
    SOURCES
        ecosystem/proxy/proxy_connector.cpp
    DEPS Astrolune::core
)
