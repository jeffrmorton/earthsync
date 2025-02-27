import 'package:flutter/material.dart';
import 'package:flutter_cube/flutter_cube.dart';
import 'package:provider/provider.dart';
import 'main.dart';

class ResonanceGlobe extends StatefulWidget {
  @override
  _ResonanceGlobeState createState() => _ResonanceGlobeState();
}

class _ResonanceGlobeState extends State<ResonanceGlobe> with SingleTickerProviderStateMixin {
  late Scene _scene;
  late Object _earth;
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: Duration(seconds: 10))..repeat();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _scene = Scene(world: Group(), camera: Camera()..z = 5);
    _earth = Object(fileName: 'assets/earth.obj', scale: Vector3.all(2.0), rotation: Vector3(0, 0, 23.5));
    _scene.world.add(_earth);
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<ResonanceModel>(
      builder: (context, model, child) => Cube(
        onSceneCreated: (Scene scene) {
          scene.world.add(_earth);
          scene.camera = _scene.camera;
          _controller.addListener(() {
            _earth.rotation.y += 1;
            _earth.scale.setValues(2.0 + (model.frequency - 7.83) * 0.1, 2.0 + (model.frequency - 7.83) * 0.1, 2.0 + (model.frequency - 7.83) * 0.1);
            scene.update();
          });
        },
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }
}