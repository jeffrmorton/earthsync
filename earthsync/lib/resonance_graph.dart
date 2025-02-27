import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:provider/provider.dart';
import 'main.dart';

class ResonanceGraph extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Consumer<ResonanceModel>(
      builder: (context, model, child) => LineChart(
        LineChartData(
          lineBarsData: [
            LineChartBarData(
              spots: model.history.map((e) => FlSpot(e['time']! - model.history.first['time']!, e['frequency']!)).toList(),
              isCurved: true,
              color: Colors.teal[300],
              gradient: LinearGradient(
                colors: [Colors.teal[300]!, Colors.teal[700]!],
              ),
              belowBarData: BarAreaData(
                show: true,
                gradient: LinearGradient(
                  colors: [Colors.teal[300]!.withOpacity(0.3), Colors.teal[700]!.withOpacity(0.1)],
                ),
              ),
            ),
          ],
          minY: 7,
          maxY: 9,
          titlesData: FlTitlesData(
            bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                getTitlesWidget: (value, meta) => Text(
                  value.toStringAsFixed(1),
                  style: TextStyle(color: model.themeMode == 'Light' ? Colors.black54 : Colors.white70, fontSize: 12),
                ),
                reservedSize: 28,
              ),
            ),
            topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
            rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
          ),
          gridData: FlGridData(showHorizontalLines: true, horizontalInterval: 0.5),
          borderData: FlBorderData(show: false),
        ),
      ),
    );
  }
}