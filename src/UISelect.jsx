import { Children, isValidElement, useEffect, useRef, useState } from 'react';
import { Select } from '@base-ui/react/select';

export function UISelect({ children, value, onChange, disabled, required, name, id, className = '', ...props }) {
  const trigger = useRef(null);
  const [fieldsetDisabled, setFieldsetDisabled] = useState(false);
  useEffect(() => {
    const fieldset = trigger.current?.closest('fieldset');
    if (!fieldset) return;
    const sync = () => setFieldsetDisabled(fieldset.disabled);
    sync(); const observer = new MutationObserver(sync);
    observer.observe(fieldset, { attributes: true, attributeFilter: ['disabled'] });
    return () => observer.disconnect();
  }, []);
  const items = [];
  const collect = (nodes, group) => Children.forEach(nodes, (node) => {
    if (!isValidElement(node)) return;
    if (node.type === 'option') items.push({ value: String(node.props.value ?? ''), label: node.props.children, disabled: node.props.disabled, group });
    else collect(node.props.children, node.type === 'optgroup' ? node.props.label : group);
  });
  collect(children);
  return <Select.Root value={String(value ?? '')} items={items} disabled={disabled || fieldsetDisabled} required={required} name={name} onValueChange={(next) => onChange?.({ target: { value: next ?? '' } })}>
    <Select.Trigger {...props} id={id} ref={trigger} type="button" className={`ui-select-trigger ${className}`}><Select.Value /><Select.Icon><i className="bi bi-chevron-down" aria-hidden="true" /></Select.Icon></Select.Trigger>
    <Select.Portal><Select.Positioner sideOffset={6} collisionPadding={12} className="ui-select-positioner" alignItemWithTrigger={false}><Select.Popup className="ui-select-popup"><Select.List>
      {items.map((item, index) => <div key={`${item.value}-${index}`}>{item.group && items[index - 1]?.group !== item.group ? <div className="ui-select-group">{item.group}</div> : null}<Select.Item value={item.value} disabled={item.disabled} className="ui-select-item"><Select.ItemText>{item.label}</Select.ItemText><Select.ItemIndicator><i className="bi bi-check2" aria-hidden="true" /></Select.ItemIndicator></Select.Item></div>)}
    </Select.List></Select.Popup></Select.Positioner></Select.Portal>
  </Select.Root>;
}
