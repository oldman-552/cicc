import {Canvas} from '@react-three/fiber';
import {OrbitControls} from '@react-three/drei';
import React,{useMemo,useState} from 'react';
import * as THREE from 'three';
import type {GraphData,GraphNode} from './types';

function Scene({graph,onSelect}:{graph:GraphData;onSelect:(n:GraphNode)=>void}){
 const layout=useMemo(()=>{
  const parents=graph.nodes.filter(n=>n.type==='INVESTIGATION'); const positions=new Map<string,[number,number,number]>();
  const radius=Math.max(3,Math.sqrt(parents.length)*2);
  parents.forEach((n,i)=>{const angle=(i/Math.max(parents.length,1))*Math.PI*2; const p:[number,number,number]=[Math.cos(angle)*radius,Math.sin(angle)*radius,0];positions.set(n.id,p);const children=graph.edges.filter(e=>e.from===n.id);children.forEach((e,j)=>{const a=j*2.399;const r=1.4+Math.sqrt(children.length)*.1;positions.set(e.to,[p[0]+Math.cos(a)*r,p[1]+Math.sin(a)*r,Math.sin(j*1.4)*r*.5])})});
  const line:number[]=[]; graph.edges.forEach(e=>{const a=positions.get(e.from),b=positions.get(e.to);if(a&&b)line.push(...a,...b)});return {positions,line:new Float32Array(line),camera:Math.max(13,radius*3.5)};
 },[graph]);
 const [dummy]=useState(()=>new THREE.Object3D());
 const groups=[graph.nodes.filter(n=>n.type==='INVESTIGATION'&&layout.positions.has(n.id)),graph.nodes.filter(n=>n.type==='SOURCE_SNAPSHOT'&&layout.positions.has(n.id)),graph.nodes.filter(n=>n.type==='ASSET_SNAPSHOT'&&layout.positions.has(n.id)),graph.nodes.filter(n=>n.type==='TECHNIQUE_SNAPSHOT'&&layout.positions.has(n.id))];
 return <><color attach="background" args={['#08171e']}/>{layout.line.length>0&&<lineSegments><bufferGeometry><bufferAttribute attach="attributes-position" args={[layout.line,3]}/></bufferGeometry><lineBasicMaterial color="#3c8b8d" transparent opacity={.6}/></lineSegments>}{groups.map((nodes,g)=><instancedMesh key={g} args={[undefined,undefined,nodes.length]} ref={mesh=>{if(mesh){nodes.forEach((n,i)=>{dummy.position.set(...layout.positions.get(n.id)!);dummy.updateMatrix();mesh.setMatrixAt(i,dummy.matrix)});mesh.instanceMatrix.needsUpdate=true;mesh.computeBoundingSphere()}}} onClick={e=>{e.stopPropagation();if(e.instanceId!==undefined&&nodes[e.instanceId])onSelect(nodes[e.instanceId])}}><sphereGeometry args={[g===0?.33:.22,16,12]}/><meshBasicMaterial color={g===0?'#50e2d0':g===1?'#b39bff':g===2?'#e6bd77':'#8ebeff'}/></instancedMesh>)}<OrbitControls makeDefault enablePan minDistance={3} maxDistance={Math.max(60,layout.camera*3)}/></>;
}
export default function Universe({graph,onSelect,reset}:{graph:GraphData;onSelect:(n:GraphNode)=>void;reset:number}){
 const distance=Math.max(14,Math.sqrt(graph.nodes.filter(n=>n.type==='INVESTIGATION').length)*7);
 return <Canvas key={reset} camera={{position:[0,0,distance],fov:45,near:.1,far:500}} dpr={[1,1.5]} frameloop="demand" gl={{antialias:true,powerPreference:'low-power'}}><Scene graph={graph} onSelect={onSelect}/></Canvas>;
}
