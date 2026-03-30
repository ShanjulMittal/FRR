import React, { useEffect, useMemo, useState } from 'react';
import { Box, Button, Chip, FormControl, InputLabel, MenuItem, Paper, Select, SelectChangeEvent, Switch, TextField, Typography } from '@mui/material';

type FieldDef = { name: string; type?: string; description?: string };
type OperatorDef = { name: string; description?: string };

type ConditionLeaf = { id: string; type: 'condition'; field: string; operator: string; value: any; not?: boolean };
type ConditionGroup = { id: string; type: 'group'; logic: 'AND'|'OR'; not?: boolean; children: Array<ConditionNode> };
type ConditionNode = ConditionLeaf | ConditionGroup;

function uid() { return Math.random().toString(36).slice(2); }

function parseJsonToTree(jsonStr?: string): ConditionGroup {
  try {
    const obj = jsonStr ? JSON.parse(jsonStr) : null;
    if (!obj || typeof obj !== 'object') return { id: uid(), type: 'group', logic: 'AND', children: [] } as ConditionGroup;
    const toNode = (o: any): ConditionNode => {
      if (o && typeof o === 'object' && o.logic && Array.isArray(o.conditions)) {
        return { id: uid(), type: 'group', logic: String(o.logic).toUpperCase() === 'OR' ? 'OR' : 'AND', not: !!o.not, children: o.conditions.map((c: any) => toNode(c)) } as ConditionGroup;
      }
      return { id: uid(), type: 'condition', field: String(o.field || ''), operator: String(o.operator || ''), value: o.value ?? '', not: !!o.not } as ConditionLeaf;
    };
    const root = toNode(obj);
    return root.type === 'group' ? root : { id: uid(), type: 'group', logic: 'AND', children: [root] };
  } catch {
    return { id: uid(), type: 'group', logic: 'AND', children: [] } as ConditionGroup;
  }
}

function treeToJson(node: ConditionNode): any {
  if (node.type === 'group') {
    return { logic: node.logic, not: !!node.not, conditions: node.children.map(treeToJson) };
  }
  return { field: node.field, operator: node.operator, value: node.value, not: !!node.not };
}

type Props = {
  value?: string;
  fields: FieldDef[];
  operators: OperatorDef[];
  readOnly?: boolean;
  onChange?: (newValue: string) => void;
};

const ConditionTreeEditor: React.FC<Props> = ({ value, fields, operators, readOnly, onChange }) => {
  const [root, setRoot] = useState<ConditionGroup>(() => parseJsonToTree(value));
  useEffect(() => { setRoot(parseJsonToTree(value)); }, [value]);

  const notify = () => { if (onChange) onChange(JSON.stringify(treeToJson(root))); };
  useEffect(() => { notify(); }, [root]);

  const addGroup = (groupId: string) => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const walk = (n: ConditionNode) => {
      if (n.type === 'group') {
        if (n.id === groupId) n.children.push({ id: uid(), type: 'group', logic: 'AND', children: [] });
        n.children.forEach(walk);
      }
    };
    walk(clone);
    setRoot(clone);
  };

  const addCondition = (groupId: string) => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const walk = (n: ConditionNode) => {
      if (n.type === 'group') {
        if (n.id === groupId) n.children.push({ id: uid(), type: 'condition', field: '', operator: '', value: '' });
        n.children.forEach(walk);
      }
    };
    walk(clone);
    setRoot(clone);
  };

  const removeNode = (nodeId: string) => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const prune = (n: ConditionGroup): ConditionGroup => {
      n.children = n.children.filter(c => c.id !== nodeId).map(c => c.type === 'group' ? prune(c as ConditionGroup) : c);
      return n;
    };
    setRoot(prune(clone));
  };

  const updateGroupLogic = (groupId: string, logic: 'AND'|'OR') => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const walk = (n: ConditionNode) => {
      if (n.type === 'group') {
        if (n.id === groupId) (n as ConditionGroup).logic = logic;
        n.children.forEach(walk);
      }
    };
    walk(clone);
    setRoot(clone);
  };

  const toggleNot = (nodeId: string) => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const walk = (n: ConditionNode) => {
      if (n.id === nodeId) (n as any).not = !(n as any).not;
      if ((n as any).children) (n as any).children.forEach(walk);
    };
    walk(clone);
    setRoot(clone);
  };

  const updateCondition = (nodeId: string, key: 'field'|'operator'|'value', val: any) => {
    if (readOnly) return;
    const clone = structuredClone(root) as ConditionGroup;
    const walk = (n: ConditionNode) => {
      if (n.type === 'condition' && n.id === nodeId) (n as any)[key] = val;
      if ((n as any).children) (n as any).children.forEach(walk);
    };
    walk(clone);
    setRoot(clone);
  };

  const renderNode = (node: ConditionNode, depth: number) => {
    if (node.type === 'group') {
      return (
        <Paper key={node.id} variant="outlined" sx={{ p: 1.5, mb: 1, ml: depth * 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip label={node.logic} color={node.logic === 'AND' ? 'primary' : 'secondary'} size="small" />
            <FormControl size="small" sx={{ minWidth: 120 }} disabled={!!readOnly}>
              <InputLabel>Logic</InputLabel>
              <Select value={node.logic} label="Logic" onChange={(e: SelectChangeEvent) => updateGroupLogic(node.id, (e.target.value as any))}>
                <MenuItem value="AND">AND</MenuItem>
                <MenuItem value="OR">OR</MenuItem>
              </Select>
            </FormControl>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption">NOT</Typography>
              <Switch checked={!!node.not} onChange={() => toggleNot(node.id)} disabled={!!readOnly} />
            </Box>
            {!readOnly && (
              <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
                <Button size="small" variant="outlined" onClick={() => addGroup(node.id)}>Add Group</Button>
                <Button size="small" variant="outlined" onClick={() => addCondition(node.id)}>Add Condition</Button>
                {depth > 0 && <Button size="small" color="error" onClick={() => removeNode(node.id)}>Remove</Button>}
              </Box>
            )}
          </Box>
          <Box sx={{ mt: 1 }}>
            {node.children.map(c => renderNode(c, depth + 1))}
          </Box>
        </Paper>
      );
    }
    return (
      <Paper key={node.id} variant="outlined" sx={{ p: 1.5, mb: 1, ml: depth * 2 }}>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1.5fr 1.5fr 2fr auto', gap: 1, alignItems: 'center' }}>
          <FormControl size="small" disabled={!!readOnly}>
            <InputLabel>Field</InputLabel>
            <Select value={node.field} label="Field" onChange={(e: SelectChangeEvent) => updateCondition(node.id, 'field', e.target.value)}>
              {fields.map(f => (<MenuItem key={f.name} value={f.name}>{f.name}</MenuItem>))}
            </Select>
          </FormControl>
          <FormControl size="small" disabled={!!readOnly}>
            <InputLabel>Operator</InputLabel>
            <Select value={node.operator} label="Operator" onChange={(e: SelectChangeEvent) => updateCondition(node.id, 'operator', e.target.value)}>
              {operators.map(op => (<MenuItem key={op.name} value={op.name}>{op.name}</MenuItem>))}
            </Select>
          </FormControl>
          <TextField size="small" value={node.value} label="Value" onChange={(e) => updateCondition(node.id, 'value', e.target.value)} disabled={!!readOnly} />
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="caption">NOT</Typography>
            <Switch checked={!!node.not} onChange={() => toggleNot(node.id)} disabled={!!readOnly} />
            {!readOnly && <Button size="small" color="error" onClick={() => removeNode(node.id)}>Remove</Button>}
          </Box>
        </Box>
      </Paper>
    );
  };

  return (
    <Box>
      {renderNode(root, 0)}
    </Box>
  );
};

export default ConditionTreeEditor;
