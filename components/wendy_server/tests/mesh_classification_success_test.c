#include "wendy_server_mesh.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static struct sockaddr_storage address(const char *text)
{
    struct sockaddr_storage result={0};struct sockaddr_in6 *v6=(void *)&result;
    v6->sin6_family=AF_INET6;assert(inet_pton(AF_INET6,text,&v6->sin6_addr)==1);
    return result;
}
int main(void)
{
    struct sockaddr_storage local=address("fd45:b891:567f::4");
    struct sockaddr_storage device=address("fd45:b891:567f::5");
    struct sockaddr_storage operator=address("fd45:b891:5680::10");
    assert(wendy_server_mesh_addresses(&local,&device));
    assert(wendy_server_mesh_addresses(&local,&operator));
    assert(wendy_server_mesh_address(&operator));
    struct sockaddr_storage routed_app=address("fd00:5678::22");
    assert(wendy_server_mesh_addresses(&local,&routed_app));
    struct sockaddr_storage lan=address("fd00:1234::5");
    struct sockaddr_storage mapped=address("::ffff:192.0.2.5");
    assert(!wendy_server_mesh_addresses(&lan,&lan));
    assert(!wendy_server_mesh_addresses(&mapped,&mapped));
    assert(!wendy_server_mesh_addresses(&lan,&operator));
    int listener=socket(AF_INET6,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in6 loopback={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    assert(!bind(listener,(struct sockaddr *)&loopback,sizeof loopback));assert(!listen(listener,1));
    socklen_t size=sizeof loopback;assert(!getsockname(listener,(struct sockaddr *)&loopback,&size));
    int client=socket(AF_INET6,SOCK_STREAM,0);assert(client>=0);
    assert(!connect(client,(struct sockaddr *)&loopback,sizeof loopback));
    int accepted=accept(listener,NULL,NULL);assert(accepted>=0);
    assert(wendy_server_mesh_socket(accepted)==0);
    close(accepted);close(client);close(listener);
    puts("normal device/operator native mesh and physical LAN resource classification: PASS");
    return 0;
}
