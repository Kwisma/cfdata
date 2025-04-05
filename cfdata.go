package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------- 数据类型定义 -----------------------

type DataCenterInfo struct {
	DataCenter string
	City       string
	IPCount    int
	MinLatency int // 毫秒
}

type ScanResult struct {
	IP          string
	DataCenter  string
	Region      string
	City        string
	LatencyStr  string
	TCPDuration time.Duration
}

type TestResult struct {
	IP         string
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	LossRate   float64
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region_zh"`
	City   string  `json:"city_zh"`
}

// ----------------------- 主程序入口 -----------------------

func main() {
	// 定义命令行参数
	scanThreads := flag.Int("scan", 100, "扫描阶段最大并发数")
	testThreads := flag.Int("test", 50, "详细测试阶段最大并发数")
	portFlag := flag.Int("port", 443, "详细测试使用的端口")
	delay := flag.Int("delay", 500, "延迟阈值，单位毫秒")
	flag.Parse()

	// 检查 ip.csv 是否存在
	_, err := os.Stat("ip.csv")
	updateChoice := "n"
	if err == nil {
		// 文件存在时提示用户是否更新
		for {
			fmt.Print("检测到 ip.csv 文件已存在，是否更新数据？(y/n, 默认n): ")
			input, err := readLine()
			if err != nil {
				fmt.Println("读取输入错误:", err)
				continue
			}
			if input == "" {
				input = "n"
			}
			input = strings.ToLower(strings.TrimSpace(input))
			if input == "y" || input == "n" {
				updateChoice = input
				break
			}
			fmt.Println("输入无效，请输入 y 或 n！")
		}
	} else {
		// 文件不存在，直接更新数据
		updateChoice = "y"
	}

	if updateChoice == "y" {
		// 用户选择更新数据，询问测试 IPv4 或 IPv6
		var ipType int
		for {
			fmt.Print("请选择测试IPv4还是IPv6 (输入4或6，直接回车默认4): ")
			input, err := readLine()
			if err != nil {
				fmt.Println("读取输入错误:", err)
				continue
			}
			if input == "" {
				ipType = 4
				break
			}
			ipType, err = strconv.Atoi(input)
			if err != nil || (ipType != 4 && ipType != 6) {
				fmt.Println("输入无效，请输入4或6！")
				continue
			}
			break
		}
		fmt.Printf("你选择的是: IPv%d\n", ipType)
		runIPScan(ipType, *scanThreads)
	}

	// 从 ip.csv 中读取数据中心信息，供用户选择
	selectedDC, ipList := selectDataCenterFromCSV()
	if len(ipList) == 0 {
		fmt.Println("未找到IP地址，程序退出。")
		return
	}

	// 将IP列表写入 ip.txt（便于查看）
	err = writeIPsToFile("ip.txt", ipList)
	if err != nil {
		fmt.Println("写入 ip.txt 文件失败:", err)
	} else {
		if selectedDC == "" {
			fmt.Println("已将所有数据中心的IP地址写入 ip.txt")
		} else {
			fmt.Printf("已将数据中心 '%s' 的IP地址写入 ip.txt\n", selectedDC)
		}
	}

	// 对选中的IP列表做详细延迟和丢包测试，
	// 并写入结果CSV，同时输出横向柱状图（比例均基于 ip.txt 中的 IP 数量）
	runDetailedTest(ipList, selectedDC, *portFlag, *delay, *testThreads)

	// 修改退出逻辑：按 CTRL+C 或 回车键退出程序
	fmt.Println("\n程序执行结束，请按 CTRL+C 或 回车键退出程序。")
	exitChan := make(chan struct{})
	go func() {
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
		exitChan <- struct{}{}
	}()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	select {
	case <-signalChan:
	case <-exitChan:
	}
}

// ----------------------- 功能模块 -----------------------

// runIPScan 根据用户选择的IPv4/IPv6，从指定URL获取CIDR列表、生成随机IP，然后扫描测试数据中心信息，最终写入 ip.csv
func runIPScan(ipType int, scanMaxThreads int) {
	var filename, url string
	if ipType == 6 {
		filename = "ips-v6.txt"
		url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
	} else {
		filename = "ips-v4.txt"
		url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
	}

	// 检查本地文件是否存在
	var content string
	var err error
	if _, err = os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("文件 %s 不存在，正在从 URL %s 下载数据\n", filename, url)
		content, err = getURLContent(url)
		if err != nil {
			fmt.Println("获取 URL 内容出错:", err)
			return
		}
		err = saveToFile(filename, content)
		if err != nil {
			fmt.Println("保存文件出错:", err)
			return
		}
	} else {
		content, err = getFileContent(filename)
		if err != nil {
			fmt.Println("读取本地文件出错:", err)
			return
		}
	}

	// 提取IP列表，并随机生成IP（每个子网取一个随机IP）
	ipList := parseIPList(content)
	if ipType == 6 {
		ipList = getRandomIPv6s(ipList)
	} else {
		ipList = getRandomIPv4s(ipList)
	}

	// 下载或读取 locations.json 文件以获取数据中心位置信息
	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在，正在从 https://locations-adw.pages.dev 下载")
		resp, err := http.Get("https://locations-adw.pages.dev")
		if err != nil {
			fmt.Printf("无法下载 locations.json: %v\n", err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("无法读取响应体: %v\n", err)
			return
		}
		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		err = saveToFile("locations.json", string(body))
		if err != nil {
			fmt.Printf("保存 locations.json 失败: %v\n", err)
			return
		}
	} else {
		fmt.Println("本地 locations.json 已存在，无需重新下载")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开 locations.json: %v\n", err)
			return
		}
		defer file.Close()
		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("读取 locations.json 失败: %v\n", err)
			return
		}
		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("解析 locations.json 失败: %v\n", err)
			return
		}
	}

	// 构造 location 映射，key 为数据中心代码
	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	// 并发测试每个IP，用于获取数据中心、城市和延迟信息
	var wg sync.WaitGroup
	wg.Add(len(ipList))
	resultChan := make(chan ScanResult, len(ipList))
	thread := make(chan struct{}, scanMaxThreads)
	var count int
	total := len(ipList)
	for _, ip := range ipList {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				fmt.Printf("扫描进度: %d/%d (%.2f%%)\r", count, total, percentage)
				if count == total {
					fmt.Println("")
				}
			}()
			dialer := &net.Dialer{
				Timeout: 1 * time.Second,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
			if err != nil {
				return
			}
			defer conn.Close()
			tcpDuration := time.Since(start)
			// 用自定义 http.Client 重用连接
			start = time.Now()
			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: 1 * time.Second,
			}
			requestURL := "http://" + net.JoinHostPort(ip, "80") + "/cdn-cgi/trace"
			req, _ := http.NewRequest("GET", requestURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			duration := time.Since(start)
			maxDuration := 2 * time.Second
			if duration > maxDuration {
				return
			}
			buf := &bytes.Buffer{}
			timeoutChan := time.After(maxDuration)
			done := make(chan bool)
			go func() {
				_, _ = io.Copy(buf, resp.Body)
				done <- true
			}()
			select {
			case <-done:
			case <-timeoutChan:
				return
			}
			bodyStr := buf.String()
			if strings.Contains(bodyStr, "uag=Mozilla/5.0") {
				regex := regexp.MustCompile(`colo=([A-Z]+)`)
				matches := regex.FindStringSubmatch(bodyStr)
				if len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if ok {
						fmt.Printf("有效IP: %s, %s, 延迟: %d ms\n", ip, loc.City, tcpDuration.Milliseconds())
						resultChan <- ScanResult{IP: ip, DataCenter: dataCenter, Region: loc.Region, City: loc.City, LatencyStr: fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), TCPDuration: tcpDuration}
					} else {
						fmt.Printf("有效IP: %s, 数据中心: %s, 未知位置信息, 延迟: %d ms\n", ip, dataCenter, tcpDuration.Milliseconds())
						resultChan <- ScanResult{IP: ip, DataCenter: dataCenter, Region: "", City: "", LatencyStr: fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), TCPDuration: tcpDuration}
					}
				}
			}
		}(ip)
	}
	wg.Wait()
	close(resultChan)

	// 如果没有有效IP，直接退出程序
	if len(resultChan) == 0 {
		fmt.Println("未发现有效IP，程序退出。")
		os.Exit(1)
	}

	var results []ScanResult
	for r := range resultChan {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].TCPDuration < results[j].TCPDuration
	})
	// 将扫描结果写入 ip.csv
	file, err := os.Create("ip.csv")
	if err != nil {
		fmt.Printf("无法创建 ip.csv 文件: %v\n", err)
		return
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	writer.Write([]string{"IP地址", "数据中心", "地区", "城市", "网络延迟"})
	for _, res := range results {
		writer.Write([]string{res.IP, res.DataCenter, res.Region, res.City, res.LatencyStr})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Printf("写入 ip.csv 失败: %v\n", err)
		return
	}
	fmt.Println("扫描完成，ip.csv生成成功。")
}

// selectDataCenterFromCSV 读取 ip.csv，统计各数据中心信息供用户选择，并返回选定数据中心及对应IP列表
func selectDataCenterFromCSV() (string, []string) {
	file, err := os.Open("ip.csv")
	if err != nil {
		fmt.Println("无法打开 ip.csv:", err)
		return "", nil
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("读取 ip.csv 失败:", err)
		return "", nil
	}

	// 统计数据中心信息
	dataCenters := make(map[string]DataCenterInfo)
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 5 {
			continue
		}
		dc := record[1]
		city := record[3]
		latencyStr := record[4]
		latency := 0
		fmt.Sscanf(latencyStr, "%d", &latency)
		if info, exists := dataCenters[dc]; exists {
			info.IPCount++
			if latency < info.MinLatency {
				info.MinLatency = latency
			}
			dataCenters[dc] = info
		} else {
			dataCenters[dc] = DataCenterInfo{DataCenter: dc, City: city, IPCount: 1, MinLatency: latency}
		}
	}

	fmt.Println("请选择数据中心：")
	for _, info := range dataCenters {
		fmt.Printf("%s (%s) (IP数量: %d, 最低延迟: %d ms)\n", info.DataCenter, info.City, info.IPCount, info.MinLatency)
	}
	var selectedDC string
	for {
		fmt.Print("请输入数据中心名称（直接回车提取所有）：")
		input, err := readLine()
		if err != nil {
			fmt.Println("读取输入失败，请重试")
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			selectedDC = ""
			break
		}
		found := false
		for dc := range dataCenters {
			if strings.EqualFold(dc, input) {
				selectedDC = dc
				found = true
				break
			}
		}
		if !found {
			fmt.Println("输入数据中心无效，请重新输入。")
			continue
		}
		break
	}

	// 根据选择提取IP列表
	var ipList []string
	if selectedDC == "" {
		fmt.Println("提取所有数据中心的IP地址...")
		for i, record := range records {
			if i == 0 {
				continue
			}
			if len(record) >= 1 {
				ipList = append(ipList, record[0])
			}
		}
	} else {
		fmt.Printf("提取数据中心 '%s' 的IP地址...\n", selectedDC)
		for i, record := range records {
			if i == 0 {
				continue
			}
			if len(record) >= 2 && record[1] == selectedDC {
				ipList = append(ipList, record[0])
			}
		}
	}
	return selectedDC, ipList
}

// writeIPsToFile 将IP地址写入指定文本文件
func writeIPsToFile(filename string, ips []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, ip := range ips {
		_, err := file.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// runDetailedTest 对选中的IP列表进行详细测试（10次TCP连接测试443端口），统计延迟和丢包率，结果写入CSV文件
// 同时增加对测试结果的统计分析，并输出横向柱状图（基于 ip.txt 中的 IP 总数）
func runDetailedTest(ipList []string, selectedDC string, port int, delay int, testThreads int) {
	var wg sync.WaitGroup
	wg.Add(len(ipList))
	resultChan := make(chan TestResult, len(ipList))
	thread := make(chan struct{}, testThreads)
	var count int
	total := len(ipList)
	for _, ip := range ipList {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				count++
				perc := float64(count) / float64(total) * 100
				fmt.Printf("详细测试进度: %d/%d (%.2f%%)\r", count, total, perc)
				if count == total {
					fmt.Println("")
				}
			}()
			dialer := &net.Dialer{
				Timeout: time.Duration(delay) * time.Millisecond,
			}
			successCount := 0
			totalLatency := time.Duration(0)
			minLatency := time.Duration(math.MaxInt64)
			maxLatency := time.Duration(0)
			// 进行10次测试
			for i := 0; i < 10; i++ {
				start := time.Now()
				conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err != nil {
					continue
				}
				latency := time.Since(start)
				if latency > time.Duration(delay)*time.Millisecond {
					conn.Close()
					continue
				}
				successCount++
				totalLatency += latency
				if latency < minLatency {
					minLatency = latency
				}
				if latency > maxLatency {
					maxLatency = latency
				}
				conn.Close()
			}
			if successCount > 0 {
				avgLatency := totalLatency / time.Duration(successCount)
				lossRate := float64(10-successCount) / 10.0
				fmt.Printf("有效IP %s : 最小 %d ms, 最大 %d ms, 平均 %d ms, 丢包 %.2f%%\n",
					ip, minLatency.Milliseconds(), maxLatency.Milliseconds(), avgLatency.Milliseconds(), lossRate*100)
				resultChan <- TestResult{
					IP:         ip,
					MinLatency: minLatency,
					MaxLatency: maxLatency,
					AvgLatency: avgLatency,
					LossRate:   lossRate,
				}
			} else {
				// 未获得有效测试的 IP 视为丢包率 100%
				fmt.Printf("无效IP %s, 丢包率100%%, 已丢弃\n", ip)
			}
		}(ip)
	}
	wg.Wait()
	close(resultChan)

	// 如果没有成功测试的IP，不进行分析
	if len(resultChan) == 0 {
		fmt.Println("详细测试：未发现有效IP")
		return
	}
	var results []TestResult
	for r := range resultChan {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].LossRate == results[j].LossRate {
			return results[i].AvgLatency < results[j].AvgLatency
		}
		return results[i].LossRate < results[j].LossRate
	})

	outFilename := "result.csv"
	if selectedDC != "" {
		outFilename = selectedDC + ".csv"
	}
	file, err := os.Create(outFilename)
	if err != nil {
		fmt.Println("无法创建结果文件:", err)
		return
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	writer.Write([]string{"IP地址", "最小延迟(ms)", "最大延迟(ms)", "平均延迟(ms)", "丢包率(%)"})
	for _, res := range results {
		writer.Write([]string{
			res.IP,
			fmt.Sprintf("%d", res.MinLatency.Milliseconds()),
			fmt.Sprintf("%d", res.MaxLatency.Milliseconds()),
			fmt.Sprintf("%d", res.AvgLatency.Milliseconds()),
			fmt.Sprintf("%d", int(res.LossRate*100)),
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Println("写入结果文件时出现错误:", err)
		return
	}
	fmt.Printf("详细测试结束，结果已写入文件: %s\n", outFilename)

	// 调用分析函数，对详细测试结果进行统计分析，并输出横向柱状图（基于 ip.txt 中的 IP 总数）
	analyzeResults(results, total)
}

// analyzeResults 只输出横向柱状图
// 根据传入的测试结果以及总测试 IP 数量（ip.txt中），将成功测试的结果按丢包率桶分组（每10%一桶），
// 未成功测试的 IP 数量视为丢包率 100%
func analyzeResults(results []TestResult, totalIPs int) {
	// 对成功测试结果分桶（0%,10%,...90%）
	groups := make(map[int][]TestResult)
	for _, res := range results {
		// 按整数百分比取桶，如 5~9%归入0%，10~19%归入10%
		bucket := (int(res.LossRate*100) / 10) * 10
		groups[bucket] = append(groups[bucket], res)
	}
	// 未成功测试的 IP 数量视为 100% 丢包
	unsuccessfulCount := totalIPs - len(results)

	// 输出横向柱状图（固定 0%,10%,...,100% 桶）
	fmt.Println("------ 横向柱状图 （丢包率占比） ------")
	maxBarWidth := 50
	for bucket := 0; bucket <= 100; bucket += 10 {
		var count int
		var avgLatStr string
		if bucket == 100 {
			count = unsuccessfulCount
			avgLatStr = "N/A"
		} else {
			count = len(groups[bucket])
			if count > 0 {
				var totalLatency int64 = 0
				for _, res := range groups[bucket] {
					totalLatency += res.MinLatency.Milliseconds()
				}
				avgLat := float64(totalLatency) / float64(count)
				avgLatStr = fmt.Sprintf("%.0f ms", avgLat)
			} else {
				avgLatStr = "N/A"
			}
		}
		proportion := float64(count) / float64(totalIPs) * 100.0
		barLength := int(proportion / 100 * float64(maxBarWidth))
		bar := strings.Repeat("#", barLength)
		fmt.Printf("丢包率 %3d%% |%-50s| (%.2f%%, %d个, 平均延迟: %s)\n", bucket, bar, proportion, count, avgLatStr)
	}
}

// ----------------------- 工具函数 -----------------------

// readLine 从标准输入读取一行数据（去除换行符）
func readLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// getURLContent 根据指定URL下载内容
func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getFileContent 从本地读取指定文件的内容
func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// saveToFile 将内容保存到指定文件中
func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// parseIPList 按行解析文本内容，返回非空行组成的字符串切片
func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

// getRandomIPv4s 从类似 "xxx.xxx.xxx.xxx/24" 的CIDR中随机生成一个IPv4地址（只替换最后一段）
func getRandomIPv4s(ipList []string) []string {
	rand.Seed(time.Now().UnixNano())
	var randomIPs []string
	for _, subnet := range ipList {
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) != 4 {
			continue
		}
		octets[3] = fmt.Sprintf("%d", rand.Intn(256))
		randomIP := strings.Join(octets, ".")
		randomIPs = append(randomIPs, randomIP)
	}
	return randomIPs
}

// getRandomIPv6s 从类似 "xxxx:xxxx:xxxx::/48" 的CIDR中随机生成一个IPv6地址（保留前三组）
func getRandomIPv6s(ipList []string) []string {
	rand.Seed(time.Now().UnixNano())
	var randomIPs []string
	for _, subnet := range ipList {
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) < 3 {
			continue
		}
		sections = sections[:3]
		// 生成后三组随机数据（使总组数达到8组）
		for i := 3; i < 8; i++ {
			sections = append(sections, fmt.Sprintf("%x", rand.Intn(65536)))
		}
		randomIP := strings.Join(sections, ":")
		randomIPs = append(randomIPs, randomIP)
	}
	return randomIPs
}
