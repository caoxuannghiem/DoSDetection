from scapy.all import sniff, IP, ICMP, TCP, UDP
from collections import defaultdict
import sys
import curses
import time

ICMP_ECHO_THRESHOLD = 100
ICMP_BLACKNURSE_THRESHOLD = 100
TCP_SYN_THRESHOLD = 100
TCP_ACK_THRESHOLD = 100
TCP_RST_THRESHOLD = 100
TCP_XMAS_THRESHOLD = 100
UDP_FLOOD_THRESHOLD = 100

TIME_WINDOW = 1 

packet_counts = defaultdict(int)
paused = False
alert_active = False
last_packet_info = None
program_started = False

PROGRAM_NAME = "DOS Detection Software"

def packet_handler(packet):
    global paused, last_packet_info
    if paused:
        return
    
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        last_packet_info = (src_ip, dst_ip)  
        
        if packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            if icmp_layer.type == 8:
                packet_counts['icmp_echo'] += 1
            elif icmp_layer.type == 3 and icmp_layer.code == 3:
                packet_counts['icmp_blacknurse'] += 1
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == 'S':
                packet_counts['tcp_syn'] += 1
            elif tcp_layer.flags == 'A':
                packet_counts['tcp_ack'] += 1
            elif tcp_layer.flags == 'R':
                packet_counts['tcp_rst'] += 1
            elif tcp_layer.flags & 0x29 == 0x29:
                packet_counts['tcp_xmas'] += 1
        
        if packet.haslayer(UDP):
            packet_counts['udp_flood'] += 1

def detect_attacks():
    alert = False
    alert_messages = []

    if packet_counts['icmp_echo'] > ICMP_ECHO_THRESHOLD:
        alert = True
        alert_messages.append("ICMP Echo Flood detected")
    
    if packet_counts['icmp_blacknurse'] > ICMP_BLACKNURSE_THRESHOLD:
        alert = True
        alert_messages.append("ICMP Blacknurse Flood detected")
    
    if packet_counts['tcp_syn'] > TCP_SYN_THRESHOLD:
        alert = True
        alert_messages.append("TCP SYN Flood detected")
    
    if packet_counts['tcp_ack'] > TCP_ACK_THRESHOLD:
        alert = True
        alert_messages.append("TCP ACK Flood detected")
    
    if packet_counts['tcp_rst'] > TCP_RST_THRESHOLD:
        alert = True
        alert_messages.append("TCP RST Flood detected")
    
    if packet_counts['tcp_xmas'] > TCP_XMAS_THRESHOLD:
        alert = True
        alert_messages.append("TCP XMAS Flood detected")
    
    if packet_counts['udp_flood'] > UDP_FLOOD_THRESHOLD:
        alert = True
        alert_messages.append("UDP Flood detected")

    for key in packet_counts:
        packet_counts[key] = 0

    return alert, alert_messages

def monitor_traffic(stdscr):
    global paused, alert_active, last_packet_info, program_started

    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)

    stdscr.nodelay(1)
    stdscr.timeout(500)
    
    running_indicator = ['.  ', '.. ', '...']
    running_index = 0
    attack_indicator = ['!  ', '!! ', '!!!']
    attack_index = 0

    while True:
        if not program_started:
            stdscr.clear()
            stdscr.addstr(0, 0, PROGRAM_NAME, curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(2, 0, "Press 'm' to start monitoring.", curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(3, 0, "Press 'x' to exit the program.", curses.color_pair(1) | curses.A_BOLD)
            stdscr.refresh()
            key = stdscr.getch()

            if key == ord('m'):
                program_started = True
                stdscr.clear()
                stdscr.refresh()
            elif key == ord('x'):
                break
            continue

        if not paused:
            sniff(timeout=TIME_WINDOW, prn=packet_handler)

            alert, alert_messages = detect_attacks()
            alert_active = alert  

            stdscr.clear()  
            if alert:
                for i, message in enumerate(alert_messages):
                    stdscr.addstr(i, 0, message, curses.color_pair(3) | curses.A_BOLD)
                stdscr.addstr(len(alert_messages), 0, attack_indicator[attack_index], curses.color_pair(3) | curses.A_BOLD)
                attack_index = (attack_index + 1) % len(attack_indicator)
            else:
                stdscr.clear()  # Clear everything when returning to normal
                stdscr.addstr(0, 0, "Normal", curses.color_pair(1) | curses.A_BOLD)
                stdscr.addstr(1, 0, running_indicator[running_index], curses.color_pair(1) | curses.A_BOLD)
                running_index = (running_index + 1) % len(running_indicator)
                attack_index = 0
        
        stdscr.refresh()

        key = stdscr.getch()

        if key == ord('p'):
            paused = not paused
            stdscr.clear()  
            if paused:
                stdscr.addstr(0, 0, "Program paused. Press 'p' to resume.", curses.color_pair(2) | curses.A_BOLD)
                stdscr.addstr(1, 0, "Press 'b' to return to the main menu.", curses.color_pair(2) | curses.A_BOLD)
                if alert_active and last_packet_info:
                    src_ip, dst_ip = last_packet_info
                    stdscr.addstr(2, 0, f"Source IP: {src_ip}, Destination IP: {dst_ip}", curses.color_pair(2) | curses.A_BOLD)
                    for i, message in enumerate(alert_messages):
                        stdscr.addstr(3 + i, 0, f"Attack Type: {message}", curses.color_pair(3) | curses.A_BOLD)
                stdscr.refresh()
                while paused:  
                    key = stdscr.getch()
                    if key == ord('p'):
                        paused = False
                        stdscr.clear()
                        break
                    elif key == ord('b'):
                        program_started = False
                        paused = False
                        stdscr.clear()
                        break
            else:
                stdscr.clear()
                if alert_active:
                    for i, message in enumerate(alert_messages):
                        stdscr.addstr(i, 0, message, curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(len(alert_messages), 0, attack_indicator[attack_index], curses.color_pair(3) | curses.A_BOLD)
                else:
                    stdscr.clear()  
                    stdscr.addstr(0, 0, "Normal", curses.color_pair(1) | curses.A_BOLD)
                    stdscr.addstr(1, 0, running_indicator[running_index], curses.color_pair(1) | curses.A_BOLD)
                stdscr.refresh()

        if key == ord('x'):
            stdscr.clear()
            stdscr.addstr(0, 0, "Exiting program...", curses.color_pair(3) | curses.A_BOLD)
            stdscr.refresh()
            time.sleep(1)
            break

if __name__ == "__main__":
    try:
        curses.wrapper(monitor_traffic)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
