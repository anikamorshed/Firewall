import csv
import bisect
import ipaddress

class Firewall:
    port_lists = {"inboundtcp": [], "outboundtcp": [], "inboundudp": [], "outboundudp": []}
    ip_lists = {"inboundtcp": [], "outboundtcp": [], "inboundudp": [], "outboundudp": []}
    # We want to parse the ip addresses and ports into a list of ranges - even numbers are starting points
    # and odd numbers are ending points. Single ip/ports are considered a range of 1.
    # Then, we can make use of python's bisect to quickly identify if a given value falls into an
    # accepted range or not.
    def __init__(self, rules):
        with open(rules, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                port_list = self.port_lists[row[0] + row[1]]
                port = [int(n) for n in row[2].split("-")]
                if len(port) is 1:
                    port.append(port[0])
                port[1] += 1
                #print(port)
                x = bisect.bisect_left(port_list, port[0])
                y = bisect.bisect_left(port_list, port[1])
                #print(x)
                #print(y)
                if len(port_list) is 0 or (y is 0 and port_list[0] < port[1]):
                    port_list.insert(0, port[1])
                    port_list.insert(0, port[0])
                elif x is len(port_list) :
                    port_list.append(port[0])
                    port_list.append(port[1])
                else:
                    # range is already accepted by port list
                    if x%2 is 1 and y is x:
                        #print("did not insert")
                        #print("\n")
                        continue
                    if x is y: # not combining existing ranges
                        if port_list[x] > port[1]:
                            port_list.insert(y, port[1])
                            port_list.insert(x, port[0])
                        else:
                            # modify existing range
                            port_list[x] = min(port_list[x], port[0])
                            port_list[y+1] = max(port_list[y+1], port[1])
                    else:
                        port_list[x] = min(port_list[x], port[0])
                        port_list[y] = max(port_list[y], port[1])
                        # Deletes existing ranges that have been combined
                        # Sometimes we modify a start and end range, sometimes we don't.
                        # if we don't modify a start or end, we want to leave it, and delete less.
                        if x%2 is 1 and y%2 is 1:
                            del port_list[x: y]
                        elif x%2 is 0 and y%2 is 1:
                            del port_list[x+1: y]
                        elif x%2 is 0 and y%2 is 1:
                            del port_list[x+1: y-1]
                        else:
                            del port_list[x: y-1]
                #print(port_list)
                #print("\n")

                # do literally the same thing for IPs

                ip_list = self.ip_lists[row[0] + row[1]]
                ip = [int(ipaddress.IPv4Address(s)) for s in row[3].split("-")]
                if len(ip) is 1:
                    ip.append(ip[0])
                ip[1] += 1
                x = bisect.bisect_left(ip_list, ip[0])
                y = bisect.bisect_left(ip_list, ip[1])
                if len(ip_list) is 0 or (y is 0 and port_list[0] < port[1]):
                    ip_list.insert(0, ip[1])
                    ip_list.insert(0, ip[0])
                elif x is len(ip_list):
                    ip_list.append(ip[0])
                    ip_list.append(ip[1])
                else:
                    if x%2 is 1 and y is x:
                        #print("did not insert")
                        continue
                    if x is y:
                        if ip_list[x] > ip[1]:
                            ip_list.insert(y, ip[1])
                            ip_list.insert(x, ip[0])
                        else:
                            ip_list[x] = min(ip_list[x], ip[0])
                            ip_list[y+1] = max(ip_list[y+1], ip[1])
                    else:
                        ip_list[x] = min(ip_list[x], ip[0])
                        ip_list[y] = max(ip_list[y], ip[1])
                        if x%2 is 1 and y%2 is 1:
                            del port_list[x: y]
                        elif x%2 is 0 and y%2 is 1:
                            del port_list[x+1: y]
                        elif x%2 is 0 and y%2 is 1:
                            del port_list[x+1: y-1]
                        else:
                            del port_list[x: y-1]
                #print(x)
                #print(y)
                #print(ip_list)
                #print(ip)
                #print("\n")
    def accept_packet(self, direction, protocol, port, ip_address):
        #if the bisect returns an even number, the value would be inserted between an accepted range, and therefore
        # is valid
        port_list = self.port_lists[direction + protocol]
        ip_list = self.ip_lists[direction + protocol]
        return bisect.bisect(port_list, port) % 2 and bisect.bisect(ip_list, int(ipaddress.IPv4Address(ip_address))) % 2

    def selftest(self):
            assert self.accept_packet("outbound","udp",990,"52.12.48.9") == 1
            assert self.accept_packet("outbound","tcp",990,"52.12.48.9") == 0
            assert self.accept_packet("outbound","tcp",990,"52.12.48.9") == 0
            assert self.accept_packet("outbound","tcp",645,"192.155.10.11") == 1
            assert self.accept_packet("outbound","tcp",691,"192.155.10.11") == 0
            assert self.accept_packet("outbound","tcp",690,"192.155.10.11") == 1
            assert self.accept_packet("outbound","udp",990,"52.15.48.9") == 0

#f = Firewall("pie.csv")
#f.selftest()
