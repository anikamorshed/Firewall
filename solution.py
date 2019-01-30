import csv
import bisect
import ipaddress

class Firewall:
    # We want to parse the ip addresses and ports into a list of ranges - even numbers are starting points
    # and odd numbers are ending points. Single ip/ports are considered a range of 1.
    # Then, we can make use of python's bisect to quickly identify if a given value falls into an
    # accepted range or not
    def compose_intervals(self, interval, array): 
        if len(interval) is 1:
            interval.append(interval[0])
        interval[1] += 1
        #print(interval)
        x = bisect.bisect_left(array, interval[0])
        y = bisect.bisect_left(array, interval[1])
        #print(x)
        #print(y)
        #print(array)
        if len(array) is 0 or (y is 0 and array[0] < interval[1]):
            array.insert(0, interval[1])
            array.insert(0, interval[0])
        elif x is len(array):
            array.append(interval[0])
            array.append(interval[1])
        else:
            # range is already accepted by port list
            if x%2 is 1 and y is x:
                #print("did not insert")
                #print("\n")
                return
            elif x is y: # not combining existing ranges
                if array[x] > interval[1]:
                    array.insert(y, interval[1])
                    array.insert(x, interval[0])
                else:
                    # modify existing range
                    array[x] = min(array[x], interval[0])
                    array[y+1] = max(array[y+1], interval[1])
            else:
                if y is len(array):
                    y -= 1
                # Deletes existing ranges that have been combined
                # Sometimes we modify a start and end range, sometimes we don't.
                # if we don't modify a start or end, we want to leave it, and delete less.
                if x%2 is 1 and y%2 is 1:
                    array[y] = max(array[y], interval[1])
                    del array[x: y]
                elif x%2 is 0 and y%2 is 1:
                    array[x] = min(array[x], interval[0])
                    array[y] = max(array[y], interval[1])
                    del array[x+1: y]
                elif x%2 is 0 and y%2 is 0:
                    array[x] = min(array[x], interval[0])
                    del array[x+1: y+1]
                else:
                    del array[x: y+1]
    
    def __init__(self, rules):
        self.port_lists = {"inboundtcp": [], "outboundtcp": [], "inboundudp": [], "outboundudp": []}
        self.ip_lists = {"inboundtcp": [], "outboundtcp": [], "inboundudp": [], "outboundudp": []}
        with open(rules, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                
                port_list = self.port_lists[row[0] + row[1]]
                port = [int(n) for n in row[2].split("-")]
                self.compose_intervals(port, port_list)
                

                ip_list = self.ip_lists[row[0] + row[1]]
                ip = [int(ipaddress.IPv4Address(s)) for s in row[3].split("-")]
                self.compose_intervals(ip, ip_list)
                
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
            assert self.accept_packet("outbound","udp",0,"52.15.48.9") == 0




def test_init():
    f = Firewall("front_insert.csv")
    assert f.port_lists["inboundtcp"] == [78, 79, 80, 81]
    assert f.ip_lists["inboundtcp"] == [3232235522, 3232235523, 3232235778, 3232235779]
    w = Firewall("back_insert.csv")
    assert w.port_lists["inboundtcp"] == [80, 81, 82, 83]
    assert w.ip_lists["inboundtcp"] == [3232235778, 3232235779, 3232238594, 3232238595]
    
    w = Firewall("middle_insert.csv")
    assert w.port_lists["inboundtcp"] == [80, 81, 83, 84, 85, 86]
    assert w.ip_lists["inboundtcp"] == [3232235778, 3232235779, 3232238082, 3232238083, 3232238594, 3232238595]
    assert w.accept_packet("inbound", "tcp", 77, "192.168.1.1") == 0
    assert w.accept_packet("inbound", "tcp", 80, "192.168.1.1") == 0
    assert w.accept_packet("inbound", "tcp", 80, "192.168.1.2") == 1 
    assert w.accept_packet("inbound", "tcp", 81, "192.168.1.2") == 0
    assert w.accept_packet("inbound", "tcp", 82, "192.168.1.2") == 0
    assert w.accept_packet("inbound", "tcp", 83, "192.168.1.2") == 1 
    assert w.accept_packet("inbound", "tcp", 86, "192.168.1.2") == 0
    assert w.accept_packet("inbound", "tcp", 87777777, "192.168.1.2") == 0
    
    w = Firewall("edit_left_boundary.csv")
    assert w.port_lists["inboundtcp"] == [79, 81]
    assert w.ip_lists["inboundtcp"] == [3232235777, 3232235779]
    w = Firewall("edit_right_boundary.csv")
    assert w.port_lists["inboundtcp"] == [80, 82]
    assert w.ip_lists["inboundtcp"] == [3232235778, 3232235780]
    w = Firewall("edit_both_boundaries.csv")
    assert w.port_lists["inboundtcp"] == [79, 82]
    assert w.ip_lists["inboundtcp"] == [3232235777, 3232235780]
    w = Firewall("merge_no_overwrite.csv")
    assert w.port_lists["inboundtcp"] == [78, 81]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235779]
    w = Firewall("merge_overwrite_left.csv")
    assert w.port_lists["inboundtcp"] == [77, 81]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235779]
    w = Firewall("merge_overwrite_right.csv")
    assert w.port_lists["inboundtcp"] == [78, 82]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235780]
    w = Firewall("merge_overwrite_both.csv")
    assert w.port_lists["inboundtcp"] == [77, 82]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235780]
    w = Firewall("merge_delete_middle_range.csv")
    assert w.port_lists["inboundtcp"] == [78, 83]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235781]
    w = Firewall("merge_delete_overwrite_right.csv")
    assert w.port_lists["inboundtcp"] == [78, 84]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235782]
    w = Firewall("merge_delete_overwrite_left.csv")
    assert w.port_lists["inboundtcp"] == [77, 83]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235781]
    w = Firewall("merge_delete_overwrite_both.csv")
    assert w.port_lists["inboundtcp"] == [77, 84]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235782]
    w = Firewall("merge_x1y1.csv")
    assert w.port_lists["inboundtcp"] == [78, 95]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235792]
    w = Firewall("merge_x0y1.csv")
    assert w.port_lists["inboundtcp"] == [77, 95]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235792]
    w = Firewall("merge_x0y0.csv")
    assert w.port_lists["inboundtcp"] == [77, 96]
    assert w.ip_lists["inboundtcp"] == [3232235544, 3232235793]
    w = Firewall("merge_x1y0.csv")
    assert w.port_lists["inboundtcp"] == [78, 97]
    assert w.ip_lists["inboundtcp"] == [3232235776, 3232235793]
    w = Firewall("do_not_insert.csv")
    #print (w.ip_lists["inboundtcp"])
    #print (w.port_lists["inboundtcp"])
    assert w.port_lists["inboundtcp"] == [78, 89]
    assert w.ip_lists["inboundtcp"] == [3232235778, 3232235779]

test_init()

#f = Firewall("pie.csv")
#f.selftest()
