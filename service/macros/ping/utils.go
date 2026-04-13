package ping

import (
	"math"
	"sort"
)
import "github.com/airportr/miaospeed/utils"

func computeAvgOfPing(pings []uint16) uint16 {
	result := uint16(0)
	totalMS := pings[:]
	sort.Slice(totalMS, func(i, j int) bool { return totalMS[i] < totalMS[j] })
	mediumMS := totalMS[len(totalMS)/2]
	threshold := 300
	realCount := uint16(0)
	for _, delay := range totalMS {
		if -threshold < int(delay)-int(mediumMS) && int(delay)-int(mediumMS) < threshold {
			realCount += 1
		}
	}
	if realCount == 0 {
		return 0
	}
	for _, delay := range totalMS {
		if -threshold < int(delay)-int(mediumMS) && int(delay)-int(mediumMS) < threshold {
			result += delay / realCount
		}
	}
	return result
}

func calcAvgPing(values []uint16) uint16 {
	result := uint16(0)
	totalMS := values[:]
	var nonZeroLatencies []uint16
	if len(values) == 0 {
		return 0
	}
	// 移除0值
	for _, lat := range totalMS {
		if lat != 0 {
			nonZeroLatencies = append(nonZeroLatencies, lat)
		}
	}

	// 如果切片为空,返回0
	if len(nonZeroLatencies) == 0 {
		return 0
	}

	// 如果切片只有一个元素,直接返回该元素
	if len(nonZeroLatencies) == 1 {
		return nonZeroLatencies[0]
	}
	if len(nonZeroLatencies) == 2 {
		return (nonZeroLatencies[0] + nonZeroLatencies[1]) / 2
	}

	// 排序切片
	sort.Slice(nonZeroLatencies, func(i, j int) bool { return nonZeroLatencies[i] < nonZeroLatencies[j] })

	// 移除最高和最低延迟
	trimmedLatencies := nonZeroLatencies[1 : len(nonZeroLatencies)-1]

	// 如果移除后切片为空,返回0
	if len(trimmedLatencies) == 0 {
		return 0
	}

	if len(trimmedLatencies) == 1 {
		return trimmedLatencies[0]
	}

	// 计算平均值
	sum := uint16(0)
	for _, lat := range trimmedLatencies {
		sum += lat
	}
	average := float64(sum) / float64(len(trimmedLatencies))
	result = uint16(average)
	return result
}

func calcStdDevPing(values []uint16) float64 {
	output := make([]float64, len(values))
	for i, v := range values {
		output[i] = float64(v)
	}
	return math.Round(utils.StandardDeviation(output)*10) / 10
}
