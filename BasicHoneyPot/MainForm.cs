using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Windows.Forms;
using System.Drawing;
using System.Text;

namespace BasicHoneyPot
{
    public partial class MainForm : Form
    {

        private class ServiceInfo
        {
            public int Port { get; set; }
            public string Name { get; set; }
            public string Banner { get; set; }
            public bool RequiresAuth { get; set; }
        }

        private static readonly ServiceInfo[] Services = new[]
       {
            // Common Web Services
            new ServiceInfo { Port = 80, Name = "HTTP", Banner = "", RequiresAuth = false },
            new ServiceInfo { Port = 443, Name = "HTTPS", Banner = "", RequiresAuth = false },
            new ServiceInfo { Port = 8080, Name = "HTTP-Alt", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 8443, Name = "HTTPS-Alt", Banner = "", RequiresAuth = true },
            
            // Remote Access
            new ServiceInfo { Port = 22, Name = "SSH", Banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 23, Name = "Telnet", Banner = "\r\nWelcome to Ubuntu 20.04.2 LTS\r\nlogin: ", RequiresAuth = true },
            new ServiceInfo { Port = 3389, Name = "RDP", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 5900, Name = "VNC", Banner = "RFB 003.008\n", RequiresAuth = true },
            
            // File Transfer
            new ServiceInfo { Port = 21, Name = "FTP", Banner = "220 FTP Server Ready\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 69, Name = "TFTP", Banner = "", RequiresAuth = false },
            new ServiceInfo { Port = 2049, Name = "NFS", Banner = "", RequiresAuth = true },
            
            // Database
            new ServiceInfo { Port = 1433, Name = "MSSQL", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 1521, Name = "Oracle", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 3306, Name = "MySQL", Banner = "5.7.34-standard\n", RequiresAuth = true },
            new ServiceInfo { Port = 5432, Name = "PostgreSQL", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 27017, Name = "MongoDB", Banner = "", RequiresAuth = true },
            
            // Email
            new ServiceInfo { Port = 25, Name = "SMTP", Banner = "220 smtp.server.local ESMTP Postfix\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 110, Name = "POP3", Banner = "+OK POP3 server ready\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 143, Name = "IMAP", Banner = "* OK IMAP server ready\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 587, Name = "SMTP-TLS", Banner = "220 smtp.server.local ESMTP Postfix\r\n", RequiresAuth = true },
            
            // Network Services
            new ServiceInfo { Port = 53, Name = "DNS", Banner = "", RequiresAuth = false },
            new ServiceInfo { Port = 389, Name = "LDAP", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 636, Name = "LDAPS", Banner = "", RequiresAuth = true },
            
            // IoT/Industrial
            new ServiceInfo { Port = 502, Name = "Modbus", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 1883, Name = "MQTT", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 5683, Name = "CoAP", Banner = "", RequiresAuth = false },
            
            // Remote Management
            new ServiceInfo { Port = 161, Name = "SNMP", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 2222, Name = "SSH-Alt", Banner = "SSH-2.0-OpenSSH_7.4\r\n", RequiresAuth = true },
            new ServiceInfo { Port = 8291, Name = "Mikrotik", Banner = "", RequiresAuth = true },
            
            // Voice/Video
            new ServiceInfo { Port = 5060, Name = "SIP", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 5061, Name = "SIP-TLS", Banner = "", RequiresAuth = true },
            
            // Game Servers
            new ServiceInfo { Port = 25565, Name = "Minecraft", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 27015, Name = "Source", Banner = "", RequiresAuth = true },
            
            // Commonly Exploited Services
            new ServiceInfo { Port = 445, Name = "SMB", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 135, Name = "RPC", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 139, Name = "NetBIOS", Banner = "", RequiresAuth = true },
            
            // NoSQL Databases
            new ServiceInfo { Port = 6379, Name = "Redis", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 11211, Name = "Memcached", Banner = "", RequiresAuth = false },
            
            // DevOps Tools
            new ServiceInfo { Port = 9000, Name = "Jenkins", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 8081, Name = "Nexus", Banner = "", RequiresAuth = true },
            new ServiceInfo { Port = 5000, Name = "Docker", Banner = "", RequiresAuth = true }
        };


        private static readonly string DetailedLogFile = "honeypot_detailed.txt";
        private static readonly string SimpleIpListFile = "ip_list.txt";
        private static readonly string AuthAttemptsFile = "auth_attempts.txt";
        private static readonly Dictionary<string, DateTime> IpLog = new Dictionary<string, DateTime>();
        private static readonly object LogLock = new object();

        private Button startButton;
        private Button stopButton;
        private ListBox logListBox;
        private Label statusLabel;
        private bool isRunning = false;
        private List<TcpListener> listeners = new List<TcpListener>();
        private CancellationTokenSource cancellationSource;

        public MainForm()
        {
            InitializeComponent();
            InitializeCustomComponents();
        }

        private void InitializeCustomComponents()
        {
            this.Text = "Honeypot Service";
            this.Size = new Size(600, 400);

            // Status Label
            statusLabel = new Label
            {
                Text = "Service Status: Stopped",
                Location = new Point(10, 10),
                AutoSize = true
            };

            // Start Button
            startButton = new Button
            {
                Text = "Start Service",
                Location = new Point(10, 40),
                Size = new Size(100, 30)
            };
            startButton.Click += StartButton_Click;

            // Stop Button
            stopButton = new Button
            {
                Text = "Stop Service",
                Location = new Point(120, 40),
                Size = new Size(100, 30),
                Enabled = false
            };
            stopButton.Click += StopButton_Click;

            // Log ListBox
            logListBox = new ListBox
            {
                Location = new Point(10, 80),
                Size = new Size(565, 270),
                ScrollAlwaysVisible = true
            };

            // Add controls
            this.Controls.AddRange(new Control[] { statusLabel, startButton, stopButton, logListBox });

            // Form closing event
            this.FormClosing += MainForm_FormClosing;
        }

        private async Task HandleClient(TcpClient client, ServiceInfo service, CancellationToken token)
        {
            try
            {
                using (client)
                {
                    var ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                    LogIp(ip, service.Name);

                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream, Encoding.ASCII))
                    using (var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true })
                    {
                        // Send banner if exists
                        if (!string.IsNullOrEmpty(service.Banner))
                        {
                            await writer.WriteAsync(service.Banner);
                        }

                        if (service.RequiresAuth)
                        {
                            string username = "", password = "";

                            // Handle specific protocols
                            switch (service.Port)
                            {

                                case 3306: // MySQL
                                    await writer.WriteAsync("5.7.34-standard\n");
                                    await SendMySQLGreeting(writer);
                                    break;

                                case 6379: // Redis
                                    await writer.WriteAsync("-NOAUTH Authentication required.\r\n");
                                    await reader.ReadLineAsync(); // Wait for AUTH command
                                    await writer.WriteAsync("-ERR invalid password\r\n");
                                    break;

                                case 27017: // MongoDB
                                    await writer.WriteAsync("\"ok\" : 0, \"errmsg\" : \"Authentication failed.\", \"code\" : 18\n");
                                    break;

                                case 1433: // MSSQL
                                    await writer.WriteAsync("Login failed for user. Reason: Not associated with a trusted SQL Server connection.\n");
                                    break;

                                case 22: // SSH
                                    // Read their SSH version string
                                    string clientVersion = await reader.ReadLineAsync();
                                    LogToUI($"SSH Version from {ip}: {clientVersion}");
                                    // In real SSH, key exchange would happen here
                                    await Task.Delay(1000, token); // Simulate processing
                                    await writer.WriteAsync("Password authentication\n");
                                    break;

                                case 21: // FTP
                                    // Wait for USER command
                                    string userCmd = await reader.ReadLineAsync();
                                    if (userCmd?.StartsWith("USER ", StringComparison.OrdinalIgnoreCase) == true)
                                    {
                                        username = userCmd.Substring(5);
                                        await writer.WriteAsync("331 Password required\r\n");

                                        // Wait for PASS command
                                        string passCmd = await reader.ReadLineAsync();
                                        if (passCmd?.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase) == true)
                                        {
                                            password = passCmd.Substring(5);
                                        }
                                    }
                                    break;

                                case 23: // Telnet
                                    username = await reader.ReadLineAsync();
                                    await writer.WriteAsync("Password: ");
                                    password = await reader.ReadLineAsync();
                                    break;

                                default:
                                    // Basic auth for other services
                                    await writer.WriteAsync("login: ");
                                    username = await reader.ReadLineAsync();
                                    await writer.WriteAsync("password: ");
                                    password = await reader.ReadLineAsync();
                                    break;
                            }


                            // Log the attempt
                            if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
                            {
                                LogAuthAttempt(ip, service.Name, username, password);
                            }

                            // Simulate authentication failure after a delay
                            await Task.Delay(1000, token);
                            switch (service.Port)
                            {
                                case 21: // FTP
                                    await writer.WriteAsync("530 Login incorrect.\r\n");
                                    break;
                                case 22: // SSH
                                    await writer.WriteAsync("Access denied\n");
                                    break;
                                default:
                                    await writer.WriteAsync("Login incorrect\r\n");
                                    break;
                            }
                        }
                        else if (service.Port == 80 || service.Port == 443)
                        {
                            // For HTTP/HTTPS, read the request and send a basic response
                            string request = await reader.ReadLineAsync();
                            if (!string.IsNullOrEmpty(request))
                            {
                                LogToUI($"HTTP Request from {ip}: {request}");
                                string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>It works!</body></html>";
                                await writer.WriteAsync(response);
                            }
                        }

                        await Task.Delay(1000, token); // Delay before closing
                    }
                }
            }
            catch (Exception ex)
            {
                LogToUI($"Error handling {service.Name} client: {ex.Message}");
            }
        }

        private void LogAuthAttempt(string ip, string service, string username, string password)
        {
            string logEntry = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}|{ip}|{service}|{username}|{password}";
            File.AppendAllText(AuthAttemptsFile, logEntry + Environment.NewLine);
            LogToUI($"Auth attempt on {service} from {ip} - User: {username}, Pass: {password}");
        }

        private async Task SendMySQLGreeting(StreamWriter writer)
        {
            // Simulate MySQL initial handshake
            byte[] greeting = new byte[] {
                0x4a, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x37,
                0x2e, 0x33, 0x34, 0x00, 0x2c, 0x00, 0x00, 0x00
            };
            await writer.BaseStream.WriteAsync(greeting, 0, greeting.Length);
        }

        private void StartButton_Click(object sender, EventArgs e)
        {
            try
            {
                // Create/clear log files if they don't exist
                if (!File.Exists(SimpleIpListFile))
                {
                    File.Create(SimpleIpListFile).Dispose();
                }

                // Load existing IPs if any
                if (File.Exists(SimpleIpListFile))
                {
                    var existingIps = File.ReadAllLines(SimpleIpListFile)
                        .Where(ip => !string.IsNullOrWhiteSpace(ip))
                        .Distinct();

                    foreach (var ip in existingIps)
                    {
                        if (!IpLog.ContainsKey(ip))
                        {
                            IpLog[ip] = DateTime.UtcNow; // Assume current connections for existing IPs
                        }
                    }
                }

                isRunning = true;
                startButton.Enabled = false;
                stopButton.Enabled = true;
                statusLabel.Text = "Service Status: Running";

                cancellationSource = new CancellationTokenSource();

                // Start cleanup task
                _ = CleanupOldEntries(cancellationSource.Token);

                // Start listeners for each service
                foreach (var service in Services)
                {
                    var listener = new TcpListener(IPAddress.Any, service.Port);
                    listeners.Add(listener);
                    _ = StartListener(listener, service, cancellationSource.Token);
                }

                LogToUI($"Service started. Listening on ports: {string.Join(", ", Services.Select(s => $"{s.Port}({s.Name})"))}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                StopService();
            }
        }     
    

    private void StopButton_Click(object sender, EventArgs e)
        {
            StopService();
        }

        private void StopService()
        {
            isRunning = false;
            cancellationSource?.Cancel();

            foreach (var listener in listeners)
            {
                try
                {
                    listener.Stop();
                }
                catch { }
            }

            listeners.Clear();
            startButton.Enabled = true;
            stopButton.Enabled = false;
            statusLabel.Text = "Service Status: Stopped";
            LogToUI("Service stopped");
        }

        private async Task StartListener(TcpListener listener, ServiceInfo service, CancellationToken token)
        {
            try
            {
                listener.Start();
                LogToUI($"Started {service.Name} listener on port {service.Port}");

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        var client = await listener.AcceptTcpClientAsync();
                        _ = HandleClient(client, service, token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogToUI($"Error accepting connection on port {service.Port}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogToUI($"Error on {service.Name} port {service.Port}: {ex.Message}");
            }
            finally
            {
                try { listener.Stop(); } catch { }
            }
        }

        private void LogIp(string ip, string service)
        {
            lock (LogLock)
            {
                // Write to detailed log
                string detailedLogEntry = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}|{ip}|{service}";
                File.AppendAllText(DetailedLogFile, detailedLogEntry + Environment.NewLine);

                if (!IpLog.ContainsKey(ip))
                {
                    // Add to memory dictionary
                    IpLog[ip] = DateTime.UtcNow;

                    // Append to simple IP list
                    File.AppendAllText(SimpleIpListFile, ip + Environment.NewLine);

                    LogToUI($"New connection from: {ip} to {service}");
                }
            }
        }

        private async Task CleanupOldEntries(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromHours(1), token);

                lock (LogLock)
                {
                    var now = DateTime.UtcNow;
                    var expiredIps = IpLog.Where(kvp => (now - kvp.Value).TotalDays >= 1)
                                        .Select(kvp => kvp.Key)
                                        .ToList();

                    if (expiredIps.Any())
                    {
                        // Remove expired IPs from memory
                        foreach (var ip in expiredIps)
                        {
                            IpLog.Remove(ip);
                            LogToUI($"Removed expired IP: {ip}");
                        }

                        // Rewrite the simple IP list with current IPs only
                        File.WriteAllLines(SimpleIpListFile, IpLog.Keys);
                    }
                }
            }
        }

        private void LogToUI(string message)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => LogToUI(message)));
                return;
            }

            logListBox.Items.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {message}");
            if (logListBox.Items.Count > 1000) // Limit items to prevent memory issues
            {
                logListBox.Items.RemoveAt(logListBox.Items.Count - 1);
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopService();
        }
    }
}